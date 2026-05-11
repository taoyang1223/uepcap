import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, CheckCircle2, ChevronDown, Clock3, Copy, Layers3, Loader2, RefreshCw, Search, Upload, X, XCircle } from 'lucide-react'
import { copyText } from '../utils/clipboard'

interface SMNASMessageAnalyzerPanelProps {
  jobId: string
}

type NASDirection = 'uplink' | 'downlink' | 'unknown'
type NASFlowStatus = 'success' | 'failed' | 'in_progress'

interface SMNASStatistics {
  total_messages: number
  sm_messages: number
  uplink: number
  downlink: number
  unknown: number
  protected: number
  plain: number
  total_flows: number
  successful_flows: number
  failed_flows: number
  in_progress_flows: number
  flow_success_rate: number
  pdu_session_flows: number
}

interface SMNASTypeCount {
  code: string
  name: string
  count: number
}

interface SMNASMessage {
  id: string
  frame_number: number
  timestamp: string
  source_ip: string
  destination_ip: string
  direction: NASDirection
  message_type_code: string
  message_type: string
  security_header_type?: string
  security_header_name?: string
  sequence_number?: string
  ngap_procedure_code?: string
  ngap_pdu?: string
  wireshark_filter: string
}

interface SMNASFlowStep {
  frame_number: number
  timestamp: string
  direction: NASDirection
  message_type: string
  code: string
}

interface SMNASFlow {
  id: string
  status: NASFlowStatus
  start_frame: number
  end_frame?: number
  start_time: string
  end_time?: string
  duration_ms: number
  request_message: string
  result_message?: string
  failure_reason?: string
  step_count: number
  steps: SMNASFlowStep[]
  wireshark_filter: string
}

interface SMNASAnalysisResult {
  filename: string
  analyzed_at: string
  total_packets: number
  statistics: SMNASStatistics
  messages: SMNASMessage[]
  type_stats: SMNASTypeCount[]
  flows: SMNASFlow[]
}

interface APIResponse<T> {
  success: boolean
  data?: T
  error?: string
}

const directionLabels: Record<NASDirection, string> = {
  uplink: '上行',
  downlink: '下行',
  unknown: '未知',
}

const directionClasses: Record<NASDirection, string> = {
  uplink: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  downlink: 'bg-cyan-50 text-cyan-700 border-cyan-200',
  unknown: 'bg-slate-100 text-slate-600 border-slate-200',
}

const flowStatusLabels: Record<NASFlowStatus, string> = {
  success: '成功',
  failed: '失败',
  in_progress: '未完成',
}

const flowStatusClasses: Record<NASFlowStatus, string> = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  failed: 'bg-rose-50 text-rose-700 border-rose-200',
  in_progress: 'bg-amber-50 text-amber-700 border-amber-200',
}

export function SMNASMessageAnalyzerPanel({ jobId }: SMNASMessageAnalyzerPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<SMNASAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [statusFilter, setStatusFilter] = useState<'all' | NASFlowStatus>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [query, setQuery] = useState('')
  const [selectedFlow, setSelectedFlow] = useState<SMNASFlow | null>(null)
  const [selectedMessage, setSelectedMessage] = useState<SMNASMessage | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const handleAnalyze = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/jobs/${jobId}/sm-nas-messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 500 }),
      })
      const data = (await response.json()) as APIResponse<SMNASAnalysisResult>
      if (!data.success || !data.data) throw new Error(data.error || 'SM NAS消息分析失败')
      setResult(data.data)
      setStatusFilter('all')
      setTypeFilter('all')
      setQuery('')
      setSelectedFlow(null)
      setSelectedMessage(null)
    } catch (err) {
      setError('SM NAS消息分析失败: ' + (err as Error).message)
    } finally {
      setLoading(false)
    }
  }, [jobId])

  const filteredFlows = useMemo(() => {
    if (!result) return []
    return result.flows.filter(flow => statusFilter === 'all' || flow.status === statusFilter)
  }, [result, statusFilter])

  const filteredMessages = useMemo(() => {
    if (!result) return []
    const normalizedQuery = query.trim().toLowerCase()
    return result.messages.filter(message => {
      if (typeFilter !== 'all' && message.message_type_code !== typeFilter) return false
      if (!normalizedQuery) return true
      return [
        message.message_type,
        message.message_type_code,
        message.source_ip,
        message.destination_ip,
        String(message.frame_number),
        message.sequence_number || '',
        message.security_header_name || '',
      ].some(value => value.toLowerCase().includes(normalizedQuery))
    })
  }, [result, typeFilter, query])

  const handleCopy = useCallback(async (id: string, filter: string) => {
    const copied = await copyText(filter)
    if (!copied) return
    setCopiedId(id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const stats = result?.statistics
  const topTypes = result?.type_stats.slice(0, 6) || []

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 overflow-hidden">
      <div className={`${collapsed ? '' : 'border-b'} border-slate-200 bg-white px-5 py-4`}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-50 text-cyan-600 flex items-center justify-center border border-cyan-100">
              <Layers3 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-900">SM NAS Message Analyzer</h3>
              <p className="text-xs text-slate-500">
                {collapsed && result ? `SM NAS ${stats?.total_messages || 0} · PDU成功率 ${(stats?.flow_success_rate || 0).toFixed(1)}%` : '5GSM / PDU Session 消息与流程分析'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button onClick={handleAnalyze} disabled={loading} className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all active:scale-[0.98]">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : result ? <RefreshCw className="w-4 h-4" /> : <Upload className="w-4 h-4" />}
              <span>{loading ? '分析中...' : result ? '重新分析' : '开始分析'}</span>
            </button>
            <button onClick={() => setCollapsed(value => !value)} className="inline-flex items-center justify-center gap-2 px-3 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm font-semibold rounded-lg transition-all active:scale-[0.98]">
              <ChevronDown className={`w-4 h-4 transition-transform ${collapsed ? '' : 'rotate-180'}`} />
              <span>{collapsed ? '展开' : '收起'}</span>
            </button>
          </div>
        </div>
      </div>

      {!collapsed && (result || error || loading) && (
        <div className="p-6">
          {loading && !result && <div className="rounded-xl border border-cyan-100 bg-cyan-50 px-5 py-4 text-sm font-semibold text-cyan-700">正在分析 SM NAS 消息...</div>}
          {error && <div className="p-3 bg-red-50 rounded-lg text-red-700 text-sm font-medium">{error}</div>}

          {result && (
            <>
              <div className="mb-6 overflow-hidden rounded-xl border border-cyan-200 bg-gradient-to-r from-cyan-50 to-slate-50">
                <div className="grid grid-cols-1 gap-4 px-6 py-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
                  <div className="min-w-0">
                    <p className="text-lg font-bold text-cyan-800">分析结果</p>
                    <p className="mt-1 min-w-0 text-sm text-slate-600">
                      文件：<span title={result.filename} className="inline-block max-w-full truncate align-bottom font-mono font-semibold text-slate-900 md:max-w-[520px]">{shortFilename(result.filename)}</span>
                    </p>
                  </div>
                  <div className="grid grid-cols-3 gap-6 text-center">
                    <TopMetric label="SM NAS消息" value={stats?.total_messages || 0} />
                    <TopMetric label="PDU流程" value={stats?.pdu_session_flows || 0} accent="cyan" />
                    <TopMetric label="成功率" value={`${(stats?.flow_success_rate || 0).toFixed(1)}%`} accent="emerald" />
                  </div>
                </div>
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按 PDU Session 流程状态统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <FeatureCard active={statusFilter === 'success'} label="成功流程" value={stats?.successful_flows || 0} tone="emerald" icon={<CheckCircle2 className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'success' ? 'all' : 'success')} />
                  <FeatureCard active={statusFilter === 'failed'} label="失败流程" value={stats?.failed_flows || 0} tone="rose" icon={<XCircle className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'failed' ? 'all' : 'failed')} />
                  <FeatureCard active={statusFilter === 'in_progress'} label="未完成流程" value={stats?.in_progress_flows || 0} tone="amber" icon={<Clock3 className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'in_progress' ? 'all' : 'in_progress')} />
                </div>
              </div>

              <div className="mb-6 rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-4">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">PDU Session 流程列表</p>
                    <span className="text-sm text-slate-500">共 {filteredFlows.length} 条流程</span>
                    {statusFilter !== 'all' && <FilterPill label={`状态：${flowStatusLabels[statusFilter]}`} />}
                  </div>
                  {statusFilter !== 'all' && <button onClick={() => setStatusFilter('all')} className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700">清除筛选</button>}
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">状态</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">起始帧</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">结束帧</th>
                        <th className="px-4 py-3 text-right font-semibold text-cyan-700">耗时</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">请求</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">结果</th>
                        <th className="px-4 py-3 text-right font-semibold text-cyan-700">步骤</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {filteredFlows.map(flow => (
                        <tr key={flow.id} onClick={() => setSelectedFlow(flow)} className="cursor-pointer hover:bg-cyan-50/60">
                          <td className="px-4 py-3"><FlowStatusBadge status={flow.status} /></td>
                          <td className="px-4 py-3 font-mono text-slate-700">{flow.start_frame}</td>
                          <td className="px-4 py-3 font-mono text-slate-700">{flow.end_frame || '-'}</td>
                          <td className="px-4 py-3 text-right font-semibold tabular-nums text-slate-900">{formatDuration(flow.duration_ms)}</td>
                          <td className="px-4 py-3 text-slate-700 whitespace-nowrap">{flow.request_message}</td>
                          <td className="px-4 py-3 text-slate-700 whitespace-nowrap">{flow.failure_reason || flow.result_message || '-'}</td>
                          <td className="px-4 py-3 text-right font-semibold text-slate-700">{flow.step_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredFlows.length === 0 && <div className="py-8 text-center text-sm text-slate-500">没有匹配的 PDU Session 流程</div>}
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按 SM NAS 消息类型统计（筛选消息列表）</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {topTypes.map(item => (
                    <TypeCard key={item.code} active={typeFilter === item.code} label={item.name} code={`5GSM ${displayCode(item.code)}`} value={item.count} onClick={() => setTypeFilter(typeFilter === item.code ? 'all' : item.code)} />
                  ))}
                </div>
              </div>

              <div className="animate-fade-in rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-col gap-3 border-b border-slate-200 bg-white px-4 py-4 md:flex-row md:items-center md:justify-between">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">SM NAS 消息列表</p>
                    <span className="text-sm text-slate-500">共 {filteredMessages.length} 条记录</span>
                    {typeFilter !== 'all' && <FilterPill label="消息类型" />}
                  </div>
                  <div className="flex flex-col gap-2 md:flex-row md:items-center">
                    {(typeFilter !== 'all' || query.trim() !== '') && <button onClick={() => { setTypeFilter('all'); setQuery('') }} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700">清除消息筛选</button>}
                    <label className="relative block md:w-72">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                      <input value={query} onChange={event => setQuery(event.target.value)} className="w-full rounded-lg border border-slate-200 bg-slate-50 pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-400" placeholder="搜索 IP / 帧号 / 消息类型" />
                    </label>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">Frame</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">方向</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">消息类型</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">源 IP</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">目的 IP</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">安全头</th>
                        <th className="px-4 py-3 text-left font-semibold text-cyan-700">SEQ</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {filteredMessages.map(message => (
                        <tr key={message.id} onClick={() => setSelectedMessage(message)} className="cursor-pointer hover:bg-cyan-50/60">
                          <td className="px-4 py-3 font-mono text-slate-700">{message.frame_number}</td>
                          <td className="px-4 py-3"><DirectionBadge direction={message.direction} /></td>
                          <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{message.message_type}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600 whitespace-nowrap">{message.source_ip}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600 whitespace-nowrap">{message.destination_ip}</td>
                          <td className="px-4 py-3 text-xs text-slate-600 whitespace-nowrap">{message.security_header_name || '-'}</td>
                          <td className="px-4 py-3 font-mono text-slate-600">{message.sequence_number || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredMessages.length === 0 && <div className="py-8 text-center text-sm text-slate-500">没有匹配的 SM NAS 消息</div>}
              </div>
            </>
          )}
        </div>
      )}

      {selectedFlow && (
        <SMNASFlowDetailModal
          flow={selectedFlow}
          copied={copiedId === selectedFlow.id}
          onCopy={() => handleCopy(selectedFlow.id, selectedFlow.wireshark_filter)}
          onClose={() => setSelectedFlow(null)}
        />
      )}

      {selectedMessage && (
        <SMNASMessageDetailModal
          message={selectedMessage}
          copied={copiedId === selectedMessage.id}
          onCopy={() => handleCopy(selectedMessage.id, selectedMessage.wireshark_filter)}
          onClose={() => setSelectedMessage(null)}
        />
      )}
    </div>
  )
}

function TopMetric({ label, value, accent = 'slate' }: { label: string; value: number | string; accent?: 'slate' | 'cyan' | 'emerald' }) {
  const valueClass = accent === 'cyan' ? 'text-cyan-600' : accent === 'emerald' ? 'text-emerald-600' : 'text-slate-900'
  return (
    <div className="min-w-20">
      <p className={`text-3xl font-black tabular-nums ${valueClass}`}>{value}</p>
      <p className="mt-1 text-xs font-semibold text-slate-500">{label}</p>
    </div>
  )
}

function FeatureCard({ active, label, value, tone, icon, onClick }: { active: boolean; label: string; value: number; tone: string; icon: ReactNode; onClick: () => void }) {
  const toneClasses: Record<string, string> = {
    cyan: 'text-cyan-600 bg-cyan-50 border-cyan-200',
    emerald: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    rose: 'text-rose-600 bg-rose-50 border-rose-200',
    amber: 'text-amber-600 bg-amber-50 border-amber-200',
  }
  return (
    <button onClick={onClick} className={`min-h-24 rounded-xl border px-5 py-4 text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${toneClasses[tone]} ${active ? 'ring-2 ring-cyan-500 ring-offset-2' : ''}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-bold opacity-80">{label}</p>
          <p className="mt-2 text-3xl font-black tabular-nums">{value}</p>
        </div>
        <span className="rounded-lg bg-white/80 p-2 shadow-sm">{icon}</span>
      </div>
    </button>
  )
}

function TypeCard({ active, label, code, value, onClick }: { active: boolean; label: string; code: string; value: number; onClick: () => void }) {
  return (
    <button onClick={onClick} className={`rounded-xl border border-cyan-200 bg-cyan-50 px-5 py-4 text-left text-cyan-600 transition-all hover:-translate-y-0.5 hover:shadow-md ${active ? 'ring-2 ring-cyan-500 ring-offset-2' : ''}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="truncate text-sm font-bold text-slate-700">{label}</p>
          <p className="mt-1 text-xs font-semibold text-cyan-600">{code}</p>
        </div>
        <p className="text-3xl font-black tabular-nums">{value}</p>
      </div>
    </button>
  )
}

function DirectionBadge({ direction }: { direction: NASDirection }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${directionClasses[direction]}`}>{directionLabels[direction]}</span>
}

function FlowStatusBadge({ status }: { status: NASFlowStatus }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${flowStatusClasses[status]}`}>{flowStatusLabels[status]}</span>
}

function FilterPill({ label }: { label: string }) {
  return <span className="rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 text-xs font-bold text-cyan-700">{label}</span>
}

function SMNASFlowDetailModal({ flow, copied, onCopy, onClose }: { flow: SMNASFlow; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <ModalHeader title="PDU Session 流程详情" subtitle={`Frame ${flow.start_frame}-${flow.end_frame || flow.start_frame}`} onClose={onClose} />
        <div className="space-y-5 p-6">
          <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-bold text-cyan-700">PDU Session Establishment</p>
                <p className="mt-1 text-2xl font-black text-slate-900">{flow.failure_reason || flow.result_message || flow.request_message}</p>
              </div>
              <FlowStatusBadge status={flow.status} />
            </div>
          </div>

          <DetailSection icon={<Layers3 className="h-4 w-4" />} title="流程步骤">
            <div className="space-y-2">
              {flow.steps.map(step => (
                <div key={`${step.frame_number}:${step.code}`} className="grid grid-cols-[72px_96px_72px_1fr] items-center gap-3 rounded-lg bg-white px-3 py-2 text-sm">
                  <span className="font-mono font-bold text-slate-700">{step.frame_number}</span>
                  <span className="font-mono text-xs font-semibold text-slate-500">{formatTimestamp(step.timestamp)}</span>
                  <DirectionBadge direction={step.direction} />
                  <span className="font-semibold text-slate-800">{step.message_type}</span>
                </div>
              ))}
            </div>
          </DetailSection>

          <DetailSection icon={<Clock3 className="h-4 w-4" />} title="时间信息">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <DetailValue label="开始时间" value={formatTimestamp(flow.start_time)} />
              <DetailValue label="结束时间" value={flow.end_time ? formatTimestamp(flow.end_time) : '-'} />
              <DetailValue label="流程耗时" value={formatDuration(flow.duration_ms)} />
            </div>
          </DetailSection>

          <CopyFilter filter={flow.wireshark_filter} copied={copied} onCopy={onCopy} />
        </div>
      </div>
    </div>
  )
}

function SMNASMessageDetailModal({ message, copied, onCopy, onClose }: { message: SMNASMessage; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <ModalHeader title="SM NAS 消息详情" subtitle={`Frame ${message.frame_number} · ${message.message_type}`} onClose={onClose} />
        <div className="space-y-5 p-6">
          <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-bold text-cyan-700">5GSM · {displayCode(message.message_type_code)}</p>
                <p className="mt-1 text-2xl font-black text-slate-900">{message.message_type}</p>
              </div>
              <DirectionBadge direction={message.direction} />
            </div>
          </div>

          <DetailSection icon={<Layers3 className="h-4 w-4" />} title="网络信息">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_auto_1fr] md:items-center">
              <DetailValue label="源地址" value={message.source_ip} />
              <span className="hidden text-lg font-bold text-cyan-500 md:block">→</span>
              <DetailValue label="目的地址" value={message.destination_ip} alignRight />
            </div>
          </DetailSection>

          <DetailSection icon={<Activity className="h-4 w-4" />} title="SM NAS 信息">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <DetailValue label="时间" value={formatTimestamp(message.timestamp)} />
              <DetailValue label="Security Header" value={message.security_header_name || '-'} />
              <DetailValue label="NAS Sequence" value={message.sequence_number || '-'} />
              <DetailValue label="NGAP Procedure" value={message.ngap_procedure_code || '-'} />
              <DetailValue label="NGAP PDU" value={message.ngap_pdu || '-'} />
            </div>
          </DetailSection>

          <CopyFilter filter={message.wireshark_filter} copied={copied} onCopy={onCopy} />
        </div>
      </div>
    </div>
  )
}

function ModalHeader({ title, subtitle, onClose }: { title: string; subtitle: string; onClose: () => void }) {
  return (
    <div className="flex items-start justify-between border-b border-slate-200 px-6 py-5">
      <div className="flex items-center gap-3">
        <div className="rounded-full bg-cyan-50 p-2 text-cyan-600">
          <Activity className="h-5 w-5" />
        </div>
        <div>
          <h4 className="text-xl font-bold text-slate-900">{title}</h4>
          <p className="mt-1 text-sm font-mono text-slate-500">{subtitle}</p>
        </div>
      </div>
      <button onClick={onClose} className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700">
        <X className="h-5 w-5" />
      </button>
    </div>
  )
}

function DetailSection({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <section>
      <p className="mb-3 flex items-center gap-2 text-sm font-bold text-slate-600">
        {icon}
        <span>{title}</span>
      </p>
      <div className="rounded-xl bg-slate-50 p-4">{children}</div>
    </section>
  )
}

function DetailValue({ label, value, alignRight = false }: { label: string; value: string | number; alignRight?: boolean }) {
  return (
    <div className={alignRight ? 'text-left md:text-right' : ''}>
      <p className="mb-1 text-xs font-semibold text-slate-500">{label}</p>
      <p className="break-all font-mono text-sm font-bold text-slate-900">{value}</p>
    </div>
  )
}

function CopyFilter({ filter, copied, onCopy }: { filter: string; copied: boolean; onCopy: () => void }) {
  return (
    <DetailSection icon={<Copy className="h-4 w-4" />} title="Wireshark 过滤器">
      <div className="flex items-center justify-between gap-3 rounded-lg bg-slate-100 px-4 py-3 font-mono text-xs text-slate-700">
        <span className="break-all">{filter}</span>
        <button type="button" onClick={event => { event.preventDefault(); event.stopPropagation(); onCopy() }} className="shrink-0 rounded-md bg-white px-2 py-1 font-sans text-xs font-bold text-cyan-600 shadow-sm hover:bg-cyan-50 active:scale-95">
          {copied ? '已复制' : '复制'}
        </button>
      </div>
    </DetailSection>
  )
}

function displayCode(code: string) {
  const normalized = code.toUpperCase()
  return normalized.startsWith('0X') ? `0x${normalized.slice(2)}` : normalized
}

function formatDuration(value?: number) {
  if (value == null || Number.isNaN(value)) return '-'
  if (value < 1000) return `${value.toFixed(2)} ms`
  return `${(value / 1000).toFixed(3)} s`
}

function formatTimestamp(value?: string) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const base = date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  return `${base}.${String(date.getMilliseconds()).padStart(3, '0')}`
}

function shortFilename(filename?: string) {
  if (!filename) return '当前上传抓包'
  const parts = filename.split(/[\\/]/)
  return parts[parts.length - 1] || filename
}
