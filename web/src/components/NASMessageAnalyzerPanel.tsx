import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, CheckCircle2, ChevronDown, Clock3, Copy, KeyRound, Layers3, Loader2, Radio, RefreshCw, Search, Shield, Upload, X, XCircle } from 'lucide-react'
import { copyText } from '../utils/clipboard'
import { PaginationControls } from './PaginationControls'

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
  truncated?: boolean
  message_limit?: number
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

const categoryLabels: Record<NASCategory, string> = {
  '5gmm': '5GMM',
  '5gsm': '5GSM',
}

const PAGE_SIZE = 15

export function NASMessageAnalyzerPanel({ jobId }: NASMessageAnalyzerPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<NASAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [flowStatusFilter, setFlowStatusFilter] = useState<'all' | NASFlowStatus>('all')
  const [flowTypeFilter, setFlowTypeFilter] = useState<'all' | NASFlowType>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [query, setQuery] = useState('')
  const [listPage, setListPage] = useState(1)
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
        body: JSON.stringify({ limit: 20000 }),
      })
      const data = (await response.json()) as APIResponse<NASAnalysisResult>
      if (!data.success || !data.data) {
        throw new Error(data.error || '5GMM消息分析失败')
      }
      setResult(data.data)
      setFlowStatusFilter('all')
      setFlowTypeFilter('all')
      setTypeFilter('all')
      setQuery('')
      setListPage(1)
      setSelectedMessage(null)
      setSelectedFlow(null)
    } catch (err) {
      setError('5GMM消息分析失败: ' + (err as Error).message)
    } finally {
      setLoading(false)
    }
  }, [jobId])

  const handleCopyFlowFilter = useCallback(async (flow: NASFlow) => {
    const copied = await copyText(flow.wireshark_filter)
    if (!copied) return
    setCopiedId(flow.id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const handleCopyMessageFilter = useCallback(async (message: NASMessage) => {
    const copied = await copyText(message.wireshark_filter)
    if (!copied) return
    setCopiedId(message.id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const filteredFlows = useMemo(() => {
    if (!result) return []
    const flows = result.flows || []
    return flows.filter(flow => {
      if (flowStatusFilter !== 'all' && flow.status !== flowStatusFilter) return false
      if (flowTypeFilter !== 'all' && flow.flow_type !== flowTypeFilter) return false
      return true
    }).sort((left, right) => {
      const rightDuration = right.duration_ms ?? -1
      const leftDuration = left.duration_ms ?? -1
      if (rightDuration !== leftDuration) return rightDuration - leftDuration
      return left.start_frame - right.start_frame
    })
  }, [result, flowStatusFilter, flowTypeFilter])

  const stats = result?.statistics
  const statusCounts = useMemo(() => {
    const counts: Record<NASFlowStatus, number> = { success: 0, failed: 0, in_progress: 0 }
    for (const flow of result?.flows || []) {
      if (flowTypeFilter !== 'all' && flow.flow_type !== flowTypeFilter) continue
      counts[flow.status] += 1
    }
    return counts
  }, [result, flowTypeFilter])
  const typeCounts = useMemo(() => {
    const counts: Record<NASFlowType, number> = {
      registration: 0,
      authentication: 0,
      security_mode: 0,
      pdu_session_establishment: 0,
    }
    for (const flow of result?.flows || []) {
      if (flowStatusFilter !== 'all' && flow.status !== flowStatusFilter) continue
      counts[flow.flow_type] += 1
    }
    return counts
  }, [result, flowStatusFilter])
  const messageTypes = (result?.type_stats || []).filter(item => item.count > 0)
  const filteredMessages = useMemo(() => {
    if (!result) return []
    const messages = result.messages || []
    const normalizedQuery = query.trim().toLowerCase()
    return messages.filter(message => {
      if (typeFilter !== 'all' && `${message.category}:${message.message_type_code}` !== typeFilter) return false
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
  const hasFlowFilters = flowStatusFilter !== 'all' || flowTypeFilter !== 'all'
  const hasMessageFilters = typeFilter !== 'all' || query.trim() !== ''
  const unifiedRows = useMemo(() => {
    const includeFlows = !hasMessageFilters || hasFlowFilters
    const includeMessages = !hasFlowFilters
    const flowRows = includeFlows ? filteredFlows.map(flow => ({
      id: `flow:${flow.id}`,
      kind: 'flow' as const,
      sortFrame: flow.start_frame,
      sortDuration: flow.duration_ms ?? -1,
      flow,
      message: null,
    })) : []
    const messageRows = includeMessages ? filteredMessages.map(message => ({
      id: `msg:${message.id}`,
      kind: 'message' as const,
      sortFrame: message.frame_number,
      sortDuration: -1,
      flow: null,
      message,
    })) : []
    return [...flowRows, ...messageRows].sort((left, right) => {
      if (left.kind !== right.kind) return left.kind === 'flow' ? -1 : 1
      if (left.sortDuration !== right.sortDuration) return right.sortDuration - left.sortDuration
      return left.sortFrame - right.sortFrame
    })
  }, [filteredFlows, filteredMessages, hasFlowFilters, hasMessageFilters])
  const pagedRows = useMemo(() => paginate(unifiedRows, listPage), [unifiedRows, listPage])
  const listFlowCount = useMemo(() => unifiedRows.filter(row => row.kind === 'flow').length, [unifiedRows])
  const listMessageCount = unifiedRows.length - listFlowCount

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 overflow-hidden">
      <div className={`${collapsed ? '' : 'border-b'} border-slate-200 bg-white px-5 py-4`}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center border border-indigo-100">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-900">5GMM NAS Message Analyzer</h3>
              <p className="text-xs text-slate-500">
                {collapsed && result ? `5GMM ${stats?.total_messages || 0} · 流程成功率 ${(stats?.flow_success_rate || 0).toFixed(1)}%` : '5GMM Mobility Management 消息与流程分析'}
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
              正在分析 5GMM 消息...
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
                    <TopMetric label="5GMM消息" value={stats?.total_messages || 0} />
                    <TopMetric label="流程数" value={stats?.total_flows || 0} accent="indigo" />
                    <TopMetric label="流程成功率" value={`${(stats?.flow_success_rate || 0).toFixed(1)}%`} accent="emerald" />
                  </div>
                </div>
              </div>

              {result.truncated && (
                <div className="mb-6 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-800">
                  5G NAS 消息数量过大，已分析前 {formatCount(result.message_limit || result.total_packets)} 条匹配消息并停止继续读取，避免环境卡死。
                </div>
              )}

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按流程状态统计（可与流程类型组合）</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <FeatureCard active={flowStatusFilter === 'success'} label="成功流程" value={statusCounts.success} tone="emerald" icon={<CheckCircle2 className="w-5 h-5" />} onClick={() => { setFlowStatusFilter(flowStatusFilter === 'success' ? 'all' : 'success'); setTypeFilter('all'); setQuery(''); setListPage(1) }} />
                  <FeatureCard active={flowStatusFilter === 'failed'} label="失败流程" value={statusCounts.failed} tone="rose" icon={<XCircle className="w-5 h-5" />} onClick={() => { setFlowStatusFilter(flowStatusFilter === 'failed' ? 'all' : 'failed'); setTypeFilter('all'); setQuery(''); setListPage(1) }} />
                  <FeatureCard active={flowStatusFilter === 'in_progress'} label="未完成流程" value={statusCounts.in_progress} tone="amber" icon={<Clock3 className="w-5 h-5" />} onClick={() => { setFlowStatusFilter(flowStatusFilter === 'in_progress' ? 'all' : 'in_progress'); setTypeFilter('all'); setQuery(''); setListPage(1) }} />
                </div>
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按流程类型统计（可与流程状态组合）</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <FeatureCard active={flowTypeFilter === 'registration'} label="Registration" value={typeCounts.registration} tone="indigo" icon={<Radio className="w-5 h-5" />} onClick={() => { setFlowTypeFilter(flowTypeFilter === 'registration' ? 'all' : 'registration'); setTypeFilter('all'); setQuery(''); setListPage(1) }} />
                  <FeatureCard active={flowTypeFilter === 'authentication'} label="Authentication" value={typeCounts.authentication} tone="slate" icon={<KeyRound className="w-5 h-5" />} onClick={() => { setFlowTypeFilter(flowTypeFilter === 'authentication' ? 'all' : 'authentication'); setTypeFilter('all'); setQuery(''); setListPage(1) }} />
                  <FeatureCard active={flowTypeFilter === 'security_mode'} label="Security Mode" value={typeCounts.security_mode} tone="emerald" icon={<Shield className="w-5 h-5" />} onClick={() => { setFlowTypeFilter(flowTypeFilter === 'security_mode' ? 'all' : 'security_mode'); setTypeFilter('all'); setQuery(''); setListPage(1) }} />
                </div>
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按消息类型统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {messageTypes.map(item => (
                    <TypeCard
                      key={`${item.category}:${item.code}`}
                      active={typeFilter === `${item.category}:${item.code}`}
                      label={item.name}
                      code={`${categoryLabels[item.category]} ${displayCode(item.code)}`}
                      value={item.count}
                      onClick={() => {
                        setFlowStatusFilter('all')
                        setFlowTypeFilter('all')
                        setTypeFilter(typeFilter === `${item.category}:${item.code}` ? 'all' : `${item.category}:${item.code}`)
                        setListPage(1)
                      }}
                    />
                  ))}
                </div>
              </div>

              <div className="animate-fade-in rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-col gap-3 border-b border-slate-200 bg-white px-4 py-4 md:flex-row md:items-center md:justify-between">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">5GMM 流程 / 消息列表</p>
                    <span className="text-sm text-slate-500">共 {unifiedRows.length} 条</span>
                    <FilterPill label={`流程：${listFlowCount}`} />
                    <FilterPill label={`消息：${listMessageCount}`} />
                    {flowStatusFilter !== 'all' && <FilterPill label={`状态：${flowStatusLabels[flowStatusFilter]}`} />}
                    {flowTypeFilter !== 'all' && <FilterPill label={`流程类型：${flowTypeLabels[flowTypeFilter]}`} />}
                    {typeFilter !== 'all' && <FilterPill label="消息类型" />}
                  </div>
                  <div className="flex flex-col gap-2 md:flex-row md:items-center">
                    {(flowStatusFilter !== 'all' || flowTypeFilter !== 'all' || typeFilter !== 'all' || query.trim() !== '') && (
                      <button
                        onClick={() => {
                          setFlowStatusFilter('all')
                          setFlowTypeFilter('all')
                          setTypeFilter('all')
                          setQuery('')
                          setListPage(1)
                        }}
                        className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700"
                      >
                        清除筛选
                      </button>
                    )}
                    <label className="relative block md:w-72">
                          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                          <input
                            value={query}
                            onChange={event => { setFlowStatusFilter('all'); setFlowTypeFilter('all'); setQuery(event.target.value); setListPage(1) }}
                        className="w-full rounded-lg border border-slate-200 bg-slate-50 pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-400"
                        placeholder="搜索 IP / 帧号 / 消息类型"
                      />
                    </label>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">类型</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">名称</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">状态 / 方向</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">帧</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">源 / 请求</th>
                        <th className="px-4 py-3 text-left font-semibold text-indigo-700">目的 / 结果</th>
                        <th className="px-4 py-3 text-right font-semibold text-indigo-700">耗时 / 安全头</th>
                        <th className="px-4 py-3 text-right font-semibold text-indigo-700">步骤 / SEQ</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {pagedRows.map(row => (
                        <tr
                          key={row.id}
                          onClick={() => row.flow ? setSelectedFlow(row.flow) : row.message && setSelectedMessage(row.message)}
                          className="cursor-pointer hover:bg-indigo-50/60"
                        >
                          <td className="px-4 py-3"><RowKindBadge kind={row.kind} /></td>
                          <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">
                            {row.flow ? flowTypeLabels[row.flow.flow_type] : row.message?.message_type}
                          </td>
                          <td className="px-4 py-3">
                            {row.flow ? <FlowStatusBadge status={row.flow.status} /> : row.message ? <DirectionBadge direction={row.message.direction} /> : '-'}
                          </td>
                          <td className="px-4 py-3 font-mono text-slate-700 whitespace-nowrap">
                            {row.flow ? `${row.flow.start_frame} → ${row.flow.end_frame || '-'}` : row.message?.frame_number}
                          </td>
                          <td className="px-4 py-3 text-slate-700 whitespace-nowrap">
                            {row.flow ? row.flow.request_message : row.message?.source_ip}
                          </td>
                          <td className="px-4 py-3 text-slate-700 whitespace-nowrap">
                            {row.flow ? (row.flow.failure_reason || row.flow.result_message || '-') : row.message?.destination_ip}
                          </td>
                          <td className="px-4 py-3 text-right font-semibold tabular-nums text-slate-900">
                            {row.flow ? formatDuration(row.flow.duration_ms) : row.message?.security_header_name || '-'}
                          </td>
                          <td className="px-4 py-3 text-right font-mono font-semibold text-slate-700">
                            {row.flow ? row.flow.step_count : row.message?.sequence_number || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {unifiedRows.length === 0 && (
                  <div className="py-8 text-center text-sm text-slate-500">没有匹配的 5GMM 流程或消息</div>
                )}
                {unifiedRows.length > 0 && (
                  <PaginationControls total={unifiedRows.length} page={listPage} pageSize={PAGE_SIZE} onPageChange={setListPage} />
                )}
              </div>

            </>
          )}
        </div>
      )}

      {selectedFlow && (
        <NASFlowDetailModal
          flow={selectedFlow}
          copied={copiedId === selectedFlow.id}
          onCopy={() => handleCopyFlowFilter(selectedFlow)}
          onClose={() => setSelectedFlow(null)}
        />
      )}

      {selectedMessage && (
        <NASDetailModal
          message={selectedMessage}
          copied={copiedId === selectedMessage.id}
          onCopy={() => handleCopyMessageFilter(selectedMessage)}
          onClose={() => setSelectedMessage(null)}
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

function RowKindBadge({ kind }: { kind: 'flow' | 'message' }) {
  const classes = kind === 'flow' ? 'bg-indigo-50 text-indigo-700 border-indigo-200' : 'bg-cyan-50 text-cyan-700 border-cyan-200'
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${classes}`}>{kind === 'flow' ? '流程' : '消息'}</span>
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
              <h4 className="text-xl font-bold text-slate-900">5GMM 流程详情</h4>
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
              <h4 className="text-xl font-bold text-slate-900">5GMM 消息详情</h4>
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
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <DetailValue label="源地址" value={message.source_ip} />
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

function formatDuration(value?: number) {
  if (value == null || Number.isNaN(value)) return '-'
  if (value < 1000) return `${value.toFixed(2)} ms`
  return `${(value / 1000).toFixed(3)} s`
}

function displayCode(code: string) {
  const normalized = code.toUpperCase()
  return normalized.startsWith('0X') ? `0x${normalized.slice(2)}` : normalized
}

function paginate<T>(items: T[], page: number) {
  const pageCount = Math.max(1, Math.ceil(items.length / PAGE_SIZE))
  const safePage = Math.min(Math.max(page, 1), pageCount)
  const start = (safePage - 1) * PAGE_SIZE
  return items.slice(start, start + PAGE_SIZE)
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

function formatCount(value: number) {
  return new Intl.NumberFormat('zh-CN').format(value)
}
