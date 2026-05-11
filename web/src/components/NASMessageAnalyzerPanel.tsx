import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, CheckCircle2, ChevronDown, Clock3, Copy, KeyRound, Layers3, Loader2, Radio, RefreshCw, Search, Shield, Upload, X, XCircle } from 'lucide-react'
import { copyText } from '../utils/clipboard'

interface NASMessageAnalyzerPanelProps {
  jobId: string
}

type NASCategory = '5gmm' | '5gsm'
type NASDirection = 'uplink' | 'downlink' | 'unknown'
type NASFlowStatus = 'success' | 'failed' | 'in_progress'
type NASFlowType = 'registration' | 'authentication' | 'security_mode' | 'pdu_session_establishment'

interface NASStatistics {
  total_messages: number
  mm_messages: number
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
  registration_flows: number
  authentication_flows: number
  security_mode_flows: number
  pdu_session_flows: number
}

interface NASTypeCount {
  category: NASCategory
  code: string
  name: string
  count: number
  filter: string
}

interface NASMessage {
  id: string
  frame_number: number
  timestamp: string
  source_ip: string
  destination_ip: string
  direction: NASDirection
  category: NASCategory
  message_type_code: string
  message_type: string
  security_header_type?: string
  security_header_name?: string
  sequence_number?: string
  ngap_procedure_code?: string
  ngap_pdu?: string
  element_ids?: string[]
  wireshark_filter: string
}

interface NASFlowStep {
  frame_number: number
  timestamp: string
  direction: NASDirection
  category: NASCategory
  message_type: string
  code: string
}

interface NASFlow {
  id: string
  flow_type: NASFlowType
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
  steps: NASFlowStep[]
  wireshark_filter: string
}

interface NASAnalysisResult {
  filename: string
  analyzed_at: string
  total_packets: number
  statistics: NASStatistics
  messages: NASMessage[]
  type_stats: NASTypeCount[]
  flows: NASFlow[]
}

interface APIResponse<T> {
  success: boolean
  data?: T
  error?: string
}

const categoryLabels: Record<NASCategory, string> = {
  '5gmm': '5GMM',
  '5gsm': '5GSM',
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

const flowTypeLabels: Record<NASFlowType, string> = {
  registration: 'Registration',
  authentication: 'Authentication',
  security_mode: 'Security Mode',
  pdu_session_establishment: 'PDU Session',
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

export function NASMessageAnalyzerPanel({ jobId }: NASMessageAnalyzerPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<NASAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [categoryFilter, setCategoryFilter] = useState<'all' | NASCategory>('all')
  const [directionFilter, setDirectionFilter] = useState<'all' | NASDirection>('all')
  const [securityFilter, setSecurityFilter] = useState<'all' | 'plain' | 'protected'>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [flowStatusFilter, setFlowStatusFilter] = useState<'all' | NASFlowStatus>('all')
  const [flowTypeFilter, setFlowTypeFilter] = useState<'all' | NASFlowType>('all')
  const [query, setQuery] = useState('')
  const [selectedMessage, setSelectedMessage] = useState<NASMessage | null>(null)
  const [selectedFlow, setSelectedFlow] = useState<NASFlow | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const handleAnalyze = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/jobs/${jobId}/nas-messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 500 }),
      })
      const data = (await response.json()) as APIResponse<NASAnalysisResult>
      if (!data.success || !data.data) {
        throw new Error(data.error || 'NAS消息分析失败')
      }
      setResult(data.data)
      setCategoryFilter('all')
      setDirectionFilter('all')
      setSecurityFilter('all')
      setTypeFilter('all')
      setFlowStatusFilter('all')
      setFlowTypeFilter('all')
      setSelectedMessage(null)
      setSelectedFlow(null)
      setQuery('')
    } catch (err) {
      setError('NAS消息分析失败: ' + (err as Error).message)
    } finally {
      setLoading(false)
    }
  }, [jobId])

  const filteredMessages = useMemo(() => {
    if (!result) return []
    const normalizedQuery = query.trim().toLowerCase()
    return result.messages.filter(message => {
      if (categoryFilter !== 'all' && message.category !== categoryFilter) return false
      if (directionFilter !== 'all' && message.direction !== directionFilter) return false
      if (securityFilter === 'plain' && isProtected(message)) return false
      if (securityFilter === 'protected' && !isProtected(message)) return false
      if (typeFilter !== 'all' && typeKey(message) !== typeFilter) return false
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
  }, [result, categoryFilter, directionFilter, securityFilter, typeFilter, query])

  const handleCopyFilter = useCallback(async (message: NASMessage) => {
    const copied = await copyText(message.wireshark_filter)
    if (!copied) return
    setCopiedId(message.id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const handleCopyFlowFilter = useCallback(async (flow: NASFlow) => {
    const copied = await copyText(flow.wireshark_filter)
    if (!copied) return
    setCopiedId(flow.id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const filteredFlows = useMemo(() => {
    if (!result) return []
    return result.flows.filter(flow => {
      if (flowStatusFilter !== 'all' && flow.status !== flowStatusFilter) return false
      if (flowTypeFilter !== 'all' && flow.flow_type !== flowTypeFilter) return false
      return true
    })
  }, [result, flowStatusFilter, flowTypeFilter])

  const stats = result?.statistics
  const topTypes = result?.type_stats.slice(0, 6) || []

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 overflow-hidden">
      <div className={`${collapsed ? '' : 'border-b'} border-slate-200 bg-white px-5 py-4`}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center border border-indigo-100">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-900">NAS Message Analyzer</h3>
              <p className="text-xs text-slate-500">
                {collapsed && result ? `NAS ${stats?.total_messages || 0} · 流程成功率 ${(stats?.flow_success_rate || 0).toFixed(1)}%` : 'NAS 5GMM / 5GSM 消息与流程分析'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all active:scale-[0.98]"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : result ? <RefreshCw className="w-4 h-4" /> : <Upload className="w-4 h-4" />}
              <span>{loading ? '分析中...' : result ? '重新分析' : '开始分析'}</span>
            </button>
            <button
              onClick={() => setCollapsed(value => !value)}
              className="inline-flex items-center justify-center gap-2 px-3 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm font-semibold rounded-lg transition-all active:scale-[0.98]"
            >
              <ChevronDown className={`w-4 h-4 transition-transform ${collapsed ? '' : 'rotate-180'}`} />
              <span>{collapsed ? '展开' : '收起'}</span>
            </button>
          </div>
        </div>
      </div>

      {!collapsed && (result || error || loading) && (
        <div className="p-6">
          {loading && !result && (
            <div className="rounded-xl border border-indigo-100 bg-indigo-50 px-5 py-4 text-sm font-semibold text-indigo-700">
              正在分析 NAS 消息...
            </div>
          )}

          {error && (
            <div className="p-3 bg-red-50 rounded-lg text-red-700 text-sm font-medium">
              {error}
            </div>
          )}

          {result && (
            <>
              <div className="mb-6 overflow-hidden rounded-xl border border-indigo-200 bg-gradient-to-r from-indigo-50 to-slate-50">
                <div className="grid grid-cols-1 gap-4 px-6 py-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
                  <div className="min-w-0">
                    <p className="text-lg font-bold text-indigo-800">分析结果</p>
                    <p className="mt-1 min-w-0 text-sm text-slate-600">
                      文件：<span title={result.filename} className="inline-block max-w-full truncate align-bottom font-mono font-semibold text-slate-900 md:max-w-[520px]">{shortFilename(result.filename)}</span>
                    </p>
                  </div>
                  <div className="grid grid-cols-3 gap-6 text-center">
                    <TopMetric label="NAS消息" value={stats?.total_messages || 0} />
                    <TopMetric label="流程数" value={stats?.total_flows || 0} accent="indigo" />
                    <TopMetric label="流程成功率" value={`${(stats?.flow_success_rate || 0).toFixed(1)}%`} accent="emerald" />
                  </div>
                </div>
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按流程状态统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <FeatureCard active={flowStatusFilter === 'success'} label="成功流程" value={stats?.successful_flows || 0} tone="emerald" icon={<CheckCircle2 className="w-5 h-5" />} onClick={() => setFlowStatusFilter(flowStatusFilter === 'success' ? 'all' : 'success')} />
                  <FeatureCard active={flowStatusFilter === 'failed'} label="失败流程" value={stats?.failed_flows || 0} tone="rose" icon={<XCircle className="w-5 h-5" />} onClick={() => setFlowStatusFilter(flowStatusFilter === 'failed' ? 'all' : 'failed')} />
                  <FeatureCard active={flowStatusFilter === 'in_progress'} label="未完成流程" value={stats?.in_progress_flows || 0} tone="amber" icon={<Clock3 className="w-5 h-5" />} onClick={() => setFlowStatusFilter(flowStatusFilter === 'in_progress' ? 'all' : 'in_progress')} />
                </div>
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按流程类型统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
                  <FeatureCard active={flowTypeFilter === 'registration'} label="Registration" value={stats?.registration_flows || 0} tone="indigo" icon={<Radio className="w-5 h-5" />} onClick={() => setFlowTypeFilter(flowTypeFilter === 'registration' ? 'all' : 'registration')} />
                  <FeatureCard active={flowTypeFilter === 'authentication'} label="Authentication" value={stats?.authentication_flows || 0} tone="slate" icon={<KeyRound className="w-5 h-5" />} onClick={() => setFlowTypeFilter(flowTypeFilter === 'authentication' ? 'all' : 'authentication')} />
                  <FeatureCard active={flowTypeFilter === 'security_mode'} label="Security Mode" value={stats?.security_mode_flows || 0} tone="emerald" icon={<Shield className="w-5 h-5" />} onClick={() => setFlowTypeFilter(flowTypeFilter === 'security_mode' ? 'all' : 'security_mode')} />
                  <FeatureCard active={flowTypeFilter === 'pdu_session_establishment'} label="PDU Session" value={stats?.pdu_session_flows || 0} tone="cyan" icon={<Layers3 className="w-5 h-5" />} onClick={() => setFlowTypeFilter(flowTypeFilter === 'pdu_session_establishment' ? 'all' : 'pdu_session_establishment')} />
                </div>
              </div>

              <div className="mb-6 rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-4">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">NAS 流程列表</p>
                    <span className="text-sm text-slate-500">共 {filteredFlows.length} 条流程</span>
                    {flowStatusFilter !== 'all' && <FilterPill label={`状态：${flowStatusLabels[flowStatusFilter]}`} />}
                    {flowTypeFilter !== 'all' && <FilterPill label={`类型：${flowTypeLabels[flowTypeFilter]}`} />}
                  </div>
                  {(flowStatusFilter !== 'all' || flowTypeFilter !== 'all') && (
                    <button
                      onClick={() => {
                        setFlowStatusFilter('all')
                        setFlowTypeFilter('all')
                      }}
                      className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700"
                    >
                      清除筛选
                    </button>
                  )}
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">流程</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">状态</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">起始帧</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">结束帧</th>
                        <th className="px-4 py-3 text-right font-semibold text-indigo-700">耗时</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">请求</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">结果</th>
                        <th className="px-4 py-3 text-right font-semibold text-indigo-700">步骤</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {filteredFlows.map(flow => (
                        <tr key={flow.id} onClick={() => setSelectedFlow(flow)} className="cursor-pointer hover:bg-indigo-50/60">
                          <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{flowTypeLabels[flow.flow_type]}</td>
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
                {filteredFlows.length === 0 && (
                  <div className="py-8 text-center text-sm text-slate-500">没有匹配的 NAS 流程</div>
                )}
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按消息类型统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {topTypes.map(item => (
                    <TypeCard
                      key={`${item.category}:${item.code}`}
                      active={typeFilter === `${item.category}:${item.code}`}
                      label={item.name}
                      code={`${categoryLabels[item.category]} ${displayCode(item.code)}`}
                      value={item.count}
                      onClick={() => setTypeFilter(typeFilter === `${item.category}:${item.code}` ? 'all' : `${item.category}:${item.code}`)}
                    />
                  ))}
                </div>
              </div>

              <div className="animate-fade-in rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-col gap-3 border-b border-slate-200 bg-white px-4 py-4 md:flex-row md:items-center md:justify-between">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">NAS 消息列表</p>
                    <span className="text-sm text-slate-500">共 {filteredMessages.length} 条记录</span>
                    {categoryFilter !== 'all' && <FilterPill label={`分类：${categoryLabels[categoryFilter]}`} />}
                    {directionFilter !== 'all' && <FilterPill label={`方向：${directionLabels[directionFilter]}`} />}
                    {securityFilter !== 'all' && <FilterPill label={`安全：${securityFilter === 'plain' ? 'Plain NAS' : '安全保护'}`} />}
                    {typeFilter !== 'all' && <FilterPill label="消息类型" />}
                    {(categoryFilter !== 'all' || directionFilter !== 'all' || securityFilter !== 'all' || typeFilter !== 'all') && (
                      <button
                        onClick={() => {
                          setCategoryFilter('all')
                          setDirectionFilter('all')
                          setSecurityFilter('all')
                          setTypeFilter('all')
                        }}
                        className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700"
                      >
                        清除筛选
                      </button>
                    )}
                  </div>
                  <label className="relative block md:w-72">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      value={query}
                      onChange={event => setQuery(event.target.value)}
                      className="w-full rounded-lg border border-slate-200 bg-slate-50 pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-400"
                      placeholder="搜索 IP / 帧号 / 消息类型"
                    />
                  </label>
                </div>

                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">Frame</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">分类</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">方向</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">消息类型</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">源 IP</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">目的 IP</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">安全头</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">SEQ</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {filteredMessages.map(message => (
                        <tr
                          key={message.id}
                          onClick={() => setSelectedMessage(message)}
                          className="cursor-pointer hover:bg-indigo-50/60"
                        >
                          <td className="px-4 py-3 font-mono text-slate-700">{message.frame_number}</td>
                          <td className="px-4 py-3"><CategoryBadge category={message.category} /></td>
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

                {filteredMessages.length === 0 && (
                  <div className="py-8 text-center text-sm text-slate-500">
                    没有匹配的 NAS 消息
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {selectedMessage && (
        <NASDetailModal
          message={selectedMessage}
          copied={copiedId === selectedMessage.id}
          onCopy={() => handleCopyFilter(selectedMessage)}
          onClose={() => setSelectedMessage(null)}
        />
      )}

      {selectedFlow && (
        <NASFlowDetailModal
          flow={selectedFlow}
          copied={copiedId === selectedFlow.id}
          onCopy={() => handleCopyFlowFilter(selectedFlow)}
          onClose={() => setSelectedFlow(null)}
        />
      )}
    </div>
  )
}

function TopMetric({ label, value, accent = 'slate' }: { label: string; value: number | string; accent?: 'slate' | 'indigo' | 'cyan' | 'emerald' }) {
  const valueClass = accent === 'indigo' ? 'text-indigo-600' : accent === 'cyan' ? 'text-cyan-600' : accent === 'emerald' ? 'text-emerald-600' : 'text-slate-900'
  return (
    <div className="min-w-20">
      <p className={`text-3xl font-black tabular-nums ${valueClass}`}>{value}</p>
      <p className="mt-1 text-xs font-semibold text-slate-500">{label}</p>
    </div>
  )
}

function FeatureCard({ active, label, value, tone, icon, onClick }: { active: boolean; label: string; value: number; tone: string; icon: ReactNode; onClick: () => void }) {
  const toneClasses: Record<string, string> = {
    indigo: 'text-indigo-600 bg-indigo-50 border-indigo-200',
    cyan: 'text-cyan-600 bg-cyan-50 border-cyan-200',
    slate: 'text-slate-600 bg-slate-50 border-slate-200',
    emerald: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    rose: 'text-rose-600 bg-rose-50 border-rose-200',
    amber: 'text-amber-600 bg-amber-50 border-amber-200',
  }
  return (
    <button
      onClick={onClick}
      className={`min-h-24 rounded-xl border px-5 py-4 text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${toneClasses[tone]} ${active ? 'ring-2 ring-indigo-500 ring-offset-2' : ''}`}
    >
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
    <button
      onClick={onClick}
      className={`rounded-xl border border-indigo-200 bg-indigo-50 px-5 py-4 text-left text-indigo-600 transition-all hover:-translate-y-0.5 hover:shadow-md ${active ? 'ring-2 ring-indigo-500 ring-offset-2' : ''}`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="truncate text-sm font-bold text-slate-700">{label}</p>
          <p className="mt-1 text-xs font-semibold text-indigo-500">{code}</p>
        </div>
        <p className="text-3xl font-black tabular-nums">{value}</p>
      </div>
    </button>
  )
}

function CategoryBadge({ category }: { category: NASCategory }) {
  const classes = category === '5gmm' ? 'bg-indigo-50 text-indigo-700 border-indigo-200' : 'bg-cyan-50 text-cyan-700 border-cyan-200'
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${classes}`}>{categoryLabels[category]}</span>
}

function DirectionBadge({ direction }: { direction: NASDirection }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${directionClasses[direction]}`}>{directionLabels[direction]}</span>
}

function FlowStatusBadge({ status }: { status: NASFlowStatus }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${flowStatusClasses[status]}`}>{flowStatusLabels[status]}</span>
}

function FilterPill({ label }: { label: string }) {
  return <span className="rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 text-xs font-bold text-indigo-700">{label}</span>
}

function NASFlowDetailModal({ flow, copied, onCopy, onClose }: { flow: NASFlow; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <div className="flex items-start justify-between border-b border-slate-200 px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-indigo-50 p-2 text-indigo-600">
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <h4 className="text-xl font-bold text-slate-900">NAS 流程详情</h4>
              <p className="mt-1 text-sm font-mono text-slate-500">{flowTypeLabels[flow.flow_type]} · Frame {flow.start_frame}-{flow.end_frame || flow.start_frame}</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-5 p-6">
          <div className="rounded-xl border border-indigo-200 bg-indigo-50 px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-bold text-indigo-700">{flowTypeLabels[flow.flow_type]}</p>
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

          <DetailSection icon={<Copy className="h-4 w-4" />} title="Wireshark 过滤器">
            <div className="flex items-center justify-between gap-3 rounded-lg bg-slate-100 px-4 py-3 font-mono text-xs text-slate-700">
              <span className="break-all">{flow.wireshark_filter}</span>
              <button type="button" onClick={event => { event.preventDefault(); event.stopPropagation(); onCopy() }} className="shrink-0 rounded-md bg-white px-2 py-1 font-sans text-xs font-bold text-indigo-600 shadow-sm hover:bg-indigo-50 active:scale-95">
                {copied ? '已复制' : '复制'}
              </button>
            </div>
          </DetailSection>
        </div>
      </div>
    </div>
  )
}

function NASDetailModal({ message, copied, onCopy, onClose }: { message: NASMessage; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <div className="flex items-start justify-between border-b border-slate-200 px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-indigo-50 p-2 text-indigo-600">
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <h4 className="text-xl font-bold text-slate-900">NAS 消息详情</h4>
              <p className="mt-1 text-sm font-mono text-slate-500">Frame {message.frame_number} · {message.message_type}</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-5 p-6">
          <div className="rounded-xl border border-indigo-200 bg-indigo-50 px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-bold text-indigo-700">{categoryLabels[message.category]} · {displayCode(message.message_type_code)}</p>
                <p className="mt-1 text-2xl font-black text-slate-900">{message.message_type}</p>
              </div>
              <DirectionBadge direction={message.direction} />
            </div>
          </div>

          <DetailSection icon={<Layers3 className="h-4 w-4" />} title="网络信息">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_auto_1fr] md:items-center">
              <DetailValue label="源地址" value={message.source_ip} />
              <ArrowRight />
              <DetailValue label="目的地址" value={message.destination_ip} alignRight />
            </div>
          </DetailSection>

          <DetailSection icon={<KeyRound className="h-4 w-4" />} title="NAS 信息">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <DetailValue label="Security Header" value={message.security_header_name || '-'} />
              <DetailValue label="NAS Sequence" value={message.sequence_number || '-'} />
              <DetailValue label="NGAP Procedure" value={message.ngap_procedure_code || '-'} />
              <DetailValue label="NGAP PDU" value={message.ngap_pdu || '-'} />
            </div>
          </DetailSection>

          <DetailSection icon={<Copy className="h-4 w-4" />} title="Wireshark 过滤器">
            <div className="flex items-center justify-between gap-3 rounded-lg bg-slate-100 px-4 py-3 font-mono text-xs text-slate-700">
              <span className="break-all">{message.wireshark_filter}</span>
              <button type="button" onClick={event => { event.preventDefault(); event.stopPropagation(); onCopy() }} className="shrink-0 rounded-md bg-white px-2 py-1 font-sans text-xs font-bold text-indigo-600 shadow-sm hover:bg-indigo-50 active:scale-95">
                {copied ? '已复制' : '复制'}
              </button>
            </div>
          </DetailSection>
        </div>
      </div>
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

function ArrowRight() {
  return <span className="hidden text-lg font-bold text-indigo-500 md:block">→</span>
}

function isProtected(message: NASMessage) {
  const value = (message.security_header_type || '').trim().toLowerCase()
  return value !== '' && value !== '0' && value !== '0x0'
}

function typeKey(message: NASMessage) {
  return `${message.category}:${message.message_type_code}`
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
