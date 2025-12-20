import { useState, useMemo } from 'react'
import { ArrowLeft, Clock, Network, ChevronRight, X, Layers, ArrowRightLeft, Info, Search, ChevronDown, ChevronUp } from 'lucide-react'

// CompactPacket 结构与后端 export.go 的 CompactPacket 对应
interface CompactFrame {
  number: string
  time: string           // 相对时间
  time_absolute?: string // 绝对时间 (epoch)
  len: string
  protocols: string
}

interface CompactLayers {
  src_ip?: string
  dst_ip?: string
  src_port?: string
  dst_port?: string
  proto?: string
}

interface CompactPacket {
  frame: CompactFrame
  layers: CompactLayers
  application?: Record<string, any>
}

interface TimelineViewerProps {
  packets: CompactPacket[]
  onBack: () => void
}

// 协议颜色映射
const protocolColors: Record<string, { bg: string; text: string; border: string }> = {
  ngap: { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200' },
  'nas-5gs': { bg: 'bg-purple-50', text: 'text-purple-700', border: 'border-purple-200' },
  pfcp: { bg: 'bg-emerald-50', text: 'text-emerald-700', border: 'border-emerald-200' },
  s1ap: { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200' },
  gtpv2: { bg: 'bg-cyan-50', text: 'text-cyan-700', border: 'border-cyan-200' },
  gtp: { bg: 'bg-teal-50', text: 'text-teal-700', border: 'border-teal-200' },
}

// 获取协议的主要名称
function getMainProtocol(packet: CompactPacket): string {
  if (packet.application) {
    const protocols = Object.keys(packet.application)
    if (protocols.length > 0) return protocols[0]
  }
  return 'unknown'
}

// 获取协议的消息/过程描述
function getProtocolMessage(packet: CompactPacket): string {
  if (!packet.application) return ''
  
  for (const [proto, info] of Object.entries(packet.application)) {
    if (typeof info !== 'object' || !info) continue
    
    // NGAP - 增强显示，包含嵌套的 NAS 消息
    if (proto === 'ngap') {
      const parts: string[] = []
      
      // 主要过程名称
      if (info.procedure) {
        parts.push(info.procedure as string)
      } else if (info.procedureCode) {
        parts.push(`Procedure ${info.procedureCode}`)
      }
      
      // 嵌套的 NAS 消息
      if (info.nas && typeof info.nas === 'object') {
        const nas = info.nas as Record<string, any>
        if (nas.mm_message) {
          parts.push(`[${nas.mm_message}]`)
        } else if (nas.sm_message) {
          parts.push(`[${nas.sm_message}]`)
        }
      }
      
      if (parts.length > 0) return parts.join(' ')
    }
    // NAS-5GS
    if (proto === 'nas-5gs') {
      if (info.message) return info.message as string
      if (info.sm_message) return info.sm_message as string
    }
    // PFCP
    if (proto === 'pfcp' && info.message) {
      return info.message as string
    }
    // S1AP
    if (proto === 's1ap' && info.procedureCode) {
      return `Procedure ${info.procedureCode}`
    }
    // GTPv2
    if (proto === 'gtpv2' && info.message) {
      return info.message as string
    }
    // GTP-U
    if (proto === 'gtp' && info.message_type) {
      return `GTP-U Type ${info.message_type}`
    }
  }
  return ''
}

// 获取额外的协议标签信息
function getProtocolTags(packet: CompactPacket): { label: string; color: string }[] {
  const tags: { label: string; color: string }[] = []
  if (!packet.application) return tags
  
  for (const [proto, info] of Object.entries(packet.application)) {
    if (typeof info !== 'object' || !info) continue
    
    // NGAP 额外标签
    if (proto === 'ngap') {
      // PDU 类型
      if (info.pduType) {
        const pduType = info.pduType as string
        if (pduType.includes('initiatingMessage')) {
          tags.push({ label: 'Initiating', color: 'bg-blue-100 text-blue-700' })
        } else if (pduType.includes('successfulOutcome')) {
          tags.push({ label: 'Success', color: 'bg-green-100 text-green-700' })
        } else if (pduType.includes('unsuccessfulOutcome')) {
          tags.push({ label: 'Failure', color: 'bg-red-100 text-red-700' })
        }
      }
      
      // NAS 消息类型标签
      if (info.nas && typeof info.nas === 'object') {
        const nas = info.nas as Record<string, any>
        if (nas.security_header && nas.security_header !== '0') {
          tags.push({ label: 'Encrypted', color: 'bg-amber-100 text-amber-700' })
        }
        if (nas.msin || nas.mcc) {
          tags.push({ label: 'Identity', color: 'bg-purple-100 text-purple-700' })
        }
      }
    }
    
    // PFCP 额外标签
    if (proto === 'pfcp') {
      if (info.seid) {
        tags.push({ label: `SEID`, color: 'bg-emerald-100 text-emerald-700' })
      }
    }
    
    // GTPv2 额外标签
    if (proto === 'gtpv2') {
      if (info.teid) {
        tags.push({ label: `TEID`, color: 'bg-cyan-100 text-cyan-700' })
      }
    }
  }
  
  return tags
}

// 格式化相对时间（frame.time_relative 是相对时间，如 "0.000000000"）
function formatRelativeTime(time: string): string {
  const seconds = parseFloat(time)
  if (isNaN(seconds)) return time
  if (seconds < 1) return `${(seconds * 1000).toFixed(2)} ms`
  return `${seconds.toFixed(3)} s`
}

// 格式化绝对时间（frame.time_epoch 是 Unix 时间戳，如 "1703001234.123456789"）
// 输出格式：2024-12-20 10:30:45.123456
function formatAbsoluteTime(epochTime: string | undefined): string {
  if (!epochTime) return ''
  
  const parts = epochTime.split('.')
  const seconds = parseInt(parts[0], 10)
  const nanoStr = parts[1] || '0'
  
  if (isNaN(seconds)) return epochTime
  
  const date = new Date(seconds * 1000)
  
  // 格式化日期时间部分
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  const hours = String(date.getHours()).padStart(2, '0')
  const minutes = String(date.getMinutes()).padStart(2, '0')
  const secs = String(date.getSeconds()).padStart(2, '0')
  
  // 取纳秒的前6位（微秒精度）
  const microStr = nanoStr.padEnd(6, '0').slice(0, 6)
  
  return `${year}-${month}-${day} ${hours}:${minutes}:${secs}.${microStr}`
}

// 格式化简短绝对时间（只显示时分秒.微秒）
function formatShortAbsoluteTime(epochTime: string | undefined): string {
  if (!epochTime) return ''
  
  const parts = epochTime.split('.')
  const seconds = parseInt(parts[0], 10)
  const nanoStr = parts[1] || '0'
  
  if (isNaN(seconds)) return epochTime
  
  const date = new Date(seconds * 1000)
  
  const hours = String(date.getHours()).padStart(2, '0')
  const minutes = String(date.getMinutes()).padStart(2, '0')
  const secs = String(date.getSeconds()).padStart(2, '0')
  
  // 取纳秒的前6位（微秒精度）
  const microStr = nanoStr.padEnd(6, '0').slice(0, 6)
  
  return `${hours}:${minutes}:${secs}.${microStr}`
}

// 详情面板组件
function DetailPanel({ packet, onClose }: { packet: CompactPacket; onClose: () => void }) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['frame', 'layers', 'application']))

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev)
      if (next.has(section)) {
        next.delete(section)
      } else {
        next.add(section)
      }
      return next
    })
  }

  // 递归渲染 JSON 对象
  const renderValue = (value: any, depth: number = 0): React.ReactNode => {
    if (value === null || value === undefined) return <span className="text-slate-400">null</span>
    
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return <span className="text-slate-700 font-mono text-sm">{String(value)}</span>
    }
    
    if (Array.isArray(value)) {
      if (value.length === 0) return <span className="text-slate-400">[]</span>
      return (
        <div className="ml-4 space-y-1">
          {value.map((item, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-slate-400 text-xs">[{i}]</span>
              {renderValue(item, depth + 1)}
            </div>
          ))}
        </div>
      )
    }
    
    if (typeof value === 'object') {
      const entries = Object.entries(value)
      if (entries.length === 0) return <span className="text-slate-400">{'{}'}</span>
      return (
        <div className={depth > 0 ? 'ml-4' : ''}>
          {entries.map(([k, v]) => (
            <div key={k} className="py-0.5">
              <span className="text-indigo-600 font-medium text-sm">{k}: </span>
              {renderValue(v, depth + 1)}
            </div>
          ))}
        </div>
      )
    }
    
    return <span className="text-slate-400">{String(value)}</span>
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      
      {/* Panel */}
      <div className="relative w-full max-w-lg bg-white shadow-2xl overflow-hidden flex flex-col animate-slide-in-right">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-200 bg-gradient-to-r from-indigo-500 to-purple-600">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white/20 rounded-xl flex items-center justify-center">
              <Info className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="text-white font-bold">数据包详情</h3>
              <p className="text-white/80 text-sm">Frame #{packet.frame.number}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-white/20 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-white" />
          </button>
        </div>
        
        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Frame Info */}
          <div className="bg-slate-50 rounded-xl overflow-hidden">
            <button
              onClick={() => toggleSection('frame')}
              className="w-full flex items-center justify-between p-3 hover:bg-slate-100 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-slate-500" />
                <span className="font-semibold text-slate-700">帧信息</span>
              </div>
              {expandedSections.has('frame') ? (
                <ChevronUp className="w-4 h-4 text-slate-400" />
              ) : (
                <ChevronDown className="w-4 h-4 text-slate-400" />
              )}
            </button>
            {expandedSections.has('frame') && (
              <div className="px-3 pb-3 space-y-2">
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="bg-white p-2 rounded-lg">
                    <p className="text-slate-500 text-xs">帧号</p>
                    <p className="font-mono font-semibold text-slate-800">{packet.frame.number}</p>
                  </div>
                  <div className="bg-white p-2 rounded-lg">
                    <p className="text-slate-500 text-xs">长度</p>
                    <p className="font-mono font-semibold text-slate-800">{packet.frame.len} bytes</p>
                  </div>
                  {packet.frame.time_absolute && (
                    <div className="bg-white p-2 rounded-lg col-span-2">
                      <p className="text-slate-500 text-xs">绝对时间</p>
                      <p className="font-mono font-semibold text-slate-800">{formatAbsoluteTime(packet.frame.time_absolute)}</p>
                    </div>
                  )}
                  <div className="bg-white p-2 rounded-lg col-span-2">
                    <p className="text-slate-500 text-xs">相对时间</p>
                    <p className="font-mono font-semibold text-slate-800">{formatRelativeTime(packet.frame.time)}</p>
                  </div>
                  <div className="bg-white p-2 rounded-lg col-span-2">
                    <p className="text-slate-500 text-xs">协议栈</p>
                    <p className="font-mono text-xs text-slate-700 break-all">{packet.frame.protocols}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
          
          {/* Network Layers */}
          <div className="bg-slate-50 rounded-xl overflow-hidden">
            <button
              onClick={() => toggleSection('layers')}
              className="w-full flex items-center justify-between p-3 hover:bg-slate-100 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-slate-500" />
                <span className="font-semibold text-slate-700">网络层</span>
              </div>
              {expandedSections.has('layers') ? (
                <ChevronUp className="w-4 h-4 text-slate-400" />
              ) : (
                <ChevronDown className="w-4 h-4 text-slate-400" />
              )}
            </button>
            {expandedSections.has('layers') && (
              <div className="px-3 pb-3">
                <div className="bg-white p-3 rounded-lg space-y-2">
                  {packet.layers.proto && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-500 w-16">协议</span>
                      <span className="px-2 py-0.5 bg-slate-100 rounded text-xs font-semibold text-slate-700 uppercase">
                        {packet.layers.proto}
                      </span>
                    </div>
                  )}
                  {(packet.layers.src_ip || packet.layers.dst_ip) && (
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-mono text-slate-700">{packet.layers.src_ip || '?'}</span>
                      {packet.layers.src_port && <span className="text-slate-400">:{packet.layers.src_port}</span>}
                      <ArrowRightLeft className="w-4 h-4 text-slate-400 mx-1" />
                      <span className="font-mono text-slate-700">{packet.layers.dst_ip || '?'}</span>
                      {packet.layers.dst_port && <span className="text-slate-400">:{packet.layers.dst_port}</span>}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
          
          {/* Application Layer */}
          {packet.application && Object.keys(packet.application).length > 0 && (
            <div className="bg-slate-50 rounded-xl overflow-hidden">
              <button
                onClick={() => toggleSection('application')}
                className="w-full flex items-center justify-between p-3 hover:bg-slate-100 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-slate-500" />
                  <span className="font-semibold text-slate-700">应用层</span>
                </div>
                {expandedSections.has('application') ? (
                  <ChevronUp className="w-4 h-4 text-slate-400" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-slate-400" />
                )}
              </button>
              {expandedSections.has('application') && (
                <div className="px-3 pb-3 space-y-2">
                  {Object.entries(packet.application).map(([proto, info]) => {
                    const colors = protocolColors[proto] || { bg: 'bg-slate-50', text: 'text-slate-700', border: 'border-slate-200' }
                    return (
                      <div key={proto} className={`p-3 rounded-lg border ${colors.border} ${colors.bg}`}>
                        <div className="flex items-center gap-2 mb-2">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${colors.text} bg-white/60`}>
                            {proto}
                          </span>
                        </div>
                        <div className="text-sm">
                          {renderValue(info)}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export function TimelineViewer({ packets, onBack }: TimelineViewerProps) {
  const [selectedPacket, setSelectedPacket] = useState<CompactPacket | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [protocolFilter, setProtocolFilter] = useState<string | null>(null)

  // 获取所有协议列表
  const allProtocols = useMemo(() => {
    const protocols = new Set<string>()
    packets.forEach(p => {
      if (p.application) {
        Object.keys(p.application).forEach(proto => protocols.add(proto))
      }
    })
    return Array.from(protocols).sort()
  }, [packets])

  // 过滤数据包
  const filteredPackets = useMemo(() => {
    return packets.filter(p => {
      // 协议过滤
      if (protocolFilter) {
        if (!p.application || !p.application[protocolFilter]) return false
      }
      // 搜索过滤
      if (searchTerm) {
        const term = searchTerm.toLowerCase()
        const message = getProtocolMessage(p).toLowerCase()
        const protocols = p.frame.protocols.toLowerCase()
        const srcIp = p.layers.src_ip?.toLowerCase() || ''
        const dstIp = p.layers.dst_ip?.toLowerCase() || ''
        return message.includes(term) || protocols.includes(term) || srcIp.includes(term) || dstIp.includes(term)
      }
      return true
    })
  }, [packets, protocolFilter, searchTerm])

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-40 bg-opacity-90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="flex items-center gap-2 px-3 py-2 text-slate-600 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition-all"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="font-medium">返回</span>
            </button>
            <div className="h-8 w-px bg-slate-200" />
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-500/20">
                <Clock className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-900">数据包时间线</h1>
                <p className="text-xs text-slate-500">{packets.length} 个数据包</p>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Toolbar */}
      <div className="bg-white border-b border-slate-200 sticky top-16 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="搜索消息、IP、协议..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-50 rounded-xl text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:bg-white transition-all text-sm border border-transparent focus:border-indigo-200"
              />
            </div>
            
            {/* Protocol Filter */}
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setProtocolFilter(null)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                  protocolFilter === null
                    ? 'bg-indigo-100 text-indigo-700'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                全部
              </button>
              {allProtocols.map(proto => {
                const colors = protocolColors[proto] || { bg: 'bg-slate-100', text: 'text-slate-700', border: '' }
                return (
                  <button
                    key={proto}
                    onClick={() => setProtocolFilter(proto === protocolFilter ? null : proto)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all uppercase ${
                      protocolFilter === proto
                        ? `${colors.bg} ${colors.text}`
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    {proto}
                  </button>
                )
              })}
            </div>
            
            {/* Stats */}
            <div className="ml-auto text-sm text-slate-500">
              显示 {filteredPackets.length} / {packets.length}
            </div>
          </div>
        </div>
      </div>

      {/* Timeline */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {filteredPackets.length === 0 ? (
          <div className="text-center py-16 bg-white rounded-2xl shadow-sm">
            <div className="w-16 h-16 bg-slate-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <Network className="w-8 h-8 text-slate-300" />
            </div>
            <h3 className="text-slate-700 font-semibold mb-1">暂无数据</h3>
            <p className="text-slate-500 text-sm">没有找到匹配的数据包</p>
          </div>
        ) : (
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-[23px] top-0 bottom-0 w-0.5 bg-slate-200" />
            
            {/* Timeline items */}
            <div className="space-y-3">
              {filteredPackets.map((packet, index) => {
                const mainProto = getMainProtocol(packet)
                const message = getProtocolMessage(packet)
                const tags = getProtocolTags(packet)
                const colors = protocolColors[mainProto] || { bg: 'bg-slate-50', text: 'text-slate-700', border: 'border-slate-200' }
                
                return (
                  <div
                    key={`${packet.frame.number}-${index}`}
                    onClick={() => setSelectedPacket(packet)}
                    className="relative flex items-start gap-4 cursor-pointer group"
                  >
                    {/* Timeline dot */}
                    <div className={`relative z-10 w-3 h-3 mt-4 rounded-full border-2 border-white shadow-sm transition-transform group-hover:scale-125 ${
                      mainProto === 'ngap' ? 'bg-blue-500' :
                      mainProto === 'nas-5gs' ? 'bg-purple-500' :
                      mainProto === 'pfcp' ? 'bg-emerald-500' :
                      mainProto === 's1ap' ? 'bg-orange-500' :
                      mainProto === 'gtpv2' ? 'bg-cyan-500' :
                      mainProto === 'gtp' ? 'bg-teal-500' :
                      'bg-slate-400'
                    }`} />
                    
                    {/* Card */}
                    <div className={`flex-1 p-4 rounded-xl border transition-all group-hover:shadow-md group-hover:-translate-y-0.5 ${colors.bg} ${colors.border}`}>
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          {/* Header */}
                          <div className="flex items-center gap-2 mb-2 flex-wrap">
                            <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${colors.text} bg-white/60`}>
                              {mainProto}
                            </span>
                            {/* 额外标签 */}
                            {tags.map((tag, i) => (
                              <span key={i} className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${tag.color}`}>
                                {tag.label}
                              </span>
                            ))}
                            <span className="text-xs text-slate-500">Frame #{packet.frame.number}</span>
                            <span className="text-xs text-slate-400">•</span>
                            <span className="text-xs text-slate-500 font-mono">
                              {packet.frame.time_absolute 
                                ? formatShortAbsoluteTime(packet.frame.time_absolute)
                                : formatRelativeTime(packet.frame.time)}
                            </span>
                          </div>
                          
                          {/* Message */}
                          {message && (
                            <p className={`font-semibold mb-2 ${colors.text}`}>{message}</p>
                          )}
                          
                          {/* Network info */}
                          <div className="flex items-center gap-2 text-xs text-slate-500">
                            {packet.layers.src_ip && (
                              <>
                                <span className="font-mono">{packet.layers.src_ip}</span>
                                {packet.layers.src_port && <span>:{packet.layers.src_port}</span>}
                              </>
                            )}
                            {packet.layers.src_ip && packet.layers.dst_ip && (
                              <ArrowRightLeft className="w-3 h-3" />
                            )}
                            {packet.layers.dst_ip && (
                              <>
                                <span className="font-mono">{packet.layers.dst_ip}</span>
                                {packet.layers.dst_port && <span>:{packet.layers.dst_port}</span>}
                              </>
                            )}
                            {packet.layers.proto && (
                              <span className="ml-2 px-1.5 py-0.5 bg-white/60 rounded text-[10px] uppercase font-medium">
                                {packet.layers.proto}
                              </span>
                            )}
                          </div>
                        </div>
                        
                        {/* Arrow */}
                        <ChevronRight className="w-5 h-5 text-slate-400 group-hover:text-indigo-500 transition-colors flex-shrink-0 mt-1" />
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </main>

      {/* Detail Panel */}
      {selectedPacket && (
        <DetailPanel packet={selectedPacket} onClose={() => setSelectedPacket(null)} />
      )}

      {/* CSS for animations */}
      <style>{`
        @keyframes slide-in-right {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        .animate-slide-in-right {
          animation: slide-in-right 0.3s ease-out;
        }
      `}</style>
    </div>
  )
}
