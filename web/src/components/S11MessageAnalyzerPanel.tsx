import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, CheckCircle2, ChevronDown, Clock3, Copy, DatabaseZap, Loader2, Pause, Play, RefreshCw, RotateCw, Search, Timer, Upload, X, XCircle } from 'lucide-react'
import { copyText } from '../utils/clipboard'
import { readEventStream } from '../utils/eventStream'
import { PaginationControls } from './PaginationControls'
import { StreamProgressBar } from './StreamProgressBar'
import type { StreamProgress } from './StreamProgressBar'

interface S11MessageAnalyzerPanelProps {
  jobId: string
}

type TransactionStatus = 'success' | 'failed' | 'no_response' | 'timeout' | 'retransmit'
type ResponseTimeFilter = 'all' | 'min' | 'max'

interface S11Statistics {
  total_messages: number
  requests: number
  responses: number
  total_transactions: number
  successful: number
  failed: number
  no_response: number
  timeout: number
  retransmit: number
  success_rate: number
  create_session: number
  modify_bearer: number
  delete_session: number
  bearer_operations: number
  avg_response_time_ms: number
  max_response_time_ms: number
  min_response_time_ms: number
}

interface S11Transaction {
  id: string
  procedure: string
  status: TransactionStatus
  sequence_number: number
  request_frame: number
  response_frame?: number
  request_time: string
  response_time?: string
  response_time_ms: number
  request_type: string
  response_type?: string
  cause?: string
  cause_name?: string
  source_ip: string
  destination_ip: string
  request_teid?: string
  response_teid?: string
  apn?: string
  f_teid_ipv4?: string
  retransmit_count: number
  retransmit_frames?: number[]
  wireshark_filter: string
}

interface ProcedureCount {
  name: string
  count: number
}

interface S11AnalysisResult {
  filename: string
  analyzed_at: string
  total_packets: number
  truncated?: boolean
  message_limit?: number
  statistics: S11Statistics
  transactions: S11Transaction[]
  procedure_stats: ProcedureCount[]
}

interface StreamPayload<T> {
  progress?: StreamProgress
  result?: T
  cached?: boolean
}

const statusLabels: Record<TransactionStatus, string> = {
  success: '成功',
  failed: '失败',
  no_response: '无响应',
  timeout: '超时',
  retransmit: '重传',
}

const statusClasses: Record<TransactionStatus, string> = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  failed: 'bg-rose-50 text-rose-700 border-rose-200',
  no_response: 'bg-amber-50 text-amber-700 border-amber-200',
  timeout: 'bg-orange-50 text-orange-700 border-orange-200',
  retransmit: 'bg-purple-50 text-purple-700 border-purple-200',
}

const PAGE_SIZE = 15

export function S11MessageAnalyzerPanel({ jobId }: S11MessageAnalyzerPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<S11AnalysisResult | null>(null)
  const [progress, setProgress] = useState<StreamProgress | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [statusFilter, setStatusFilter] = useState<'all' | TransactionStatus>('all')
  const [procedureFilter, setProcedureFilter] = useState<string>('all')
  const [responseTimeFilter, setResponseTimeFilter] = useState<ResponseTimeFilter>('all')
  const [query, setQuery] = useState('')
  const [transactionPage, setTransactionPage] = useState(1)
  const [selectedTransaction, setSelectedTransaction] = useState<S11Transaction | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [paused, setPaused] = useState(false)
  const abortControllerRef = useRef<AbortController | null>(null)
  const pausedRef = useRef(false)

  const handleAnalyze = useCallback(async () => {
    abortControllerRef.current?.abort()
    const controller = new AbortController()
    abortControllerRef.current = controller
    pausedRef.current = false
    setPaused(false)
    setLoading(true)
    setError(null)
    setProgress(null)
    try {
      const response = await fetch(`/api/jobs/${jobId}/s11-messages/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({ limit: 20000, batch_rows: 10000 }),
      })
      await readEventStream<StreamPayload<S11AnalysisResult> | string>(response, ({ event, data }) => {
        if (event === 'error') {
          throw new Error(typeof data === 'string' ? data : 'S11消息分析失败')
        }
        if (event === 'progress' && typeof data === 'object') {
          setProgress((data as StreamPayload<S11AnalysisResult>).progress || {})
          return
        }
        if ((event === 'partial_result' || event === 'done') && typeof data === 'object') {
          const payload = data as StreamPayload<S11AnalysisResult>
          if (payload.progress) setProgress(payload.progress)
          if (payload.result) setResult(payload.result)
        }
      }, { isPaused: () => pausedRef.current, signal: controller.signal })
      setStatusFilter('all')
      setProcedureFilter('all')
      setResponseTimeFilter('all')
      setQuery('')
      setTransactionPage(1)
      setSelectedTransaction(null)
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        return
      }
      setError('S11消息分析失败: ' + (err as Error).message)
    } finally {
      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null
      }
      setLoading(false)
    }
  }, [jobId])

  const handlePauseToggle = useCallback(() => {
    setPaused(value => {
      pausedRef.current = !value
      return !value
    })
  }, [])

  useEffect(() => {
    return () => abortControllerRef.current?.abort()
  }, [])

  const filteredTransactions = useMemo(() => {
    if (!result) return []
    const transactions = result.transactions || []
    const targetResponseTime = responseTimeFilter === 'min'
      ? result.statistics.min_response_time_ms
      : responseTimeFilter === 'max'
        ? result.statistics.max_response_time_ms
        : null
    const normalizedQuery = query.trim().toLowerCase()
    return transactions.filter(tx => {
      if (statusFilter === 'retransmit' && (tx.retransmit_count || 0) === 0) return false
      if (statusFilter !== 'all' && statusFilter !== 'retransmit' && tx.status !== statusFilter) return false
      if (procedureFilter !== 'all' && tx.procedure !== procedureFilter) return false
      if (targetResponseTime != null && !sameResponseTime(tx.response_time_ms, targetResponseTime)) return false
      if (!normalizedQuery) return true
      return [
        tx.procedure,
        statusLabels[tx.status],
        tx.status,
        String(tx.sequence_number),
        String(tx.request_frame),
        tx.response_frame ? String(tx.response_frame) : '',
        tx.request_type,
        tx.response_type || '',
        tx.cause || '',
        tx.cause_name || '',
        tx.source_ip,
        tx.destination_ip,
        tx.request_teid || '',
        tx.response_teid || '',
        tx.apn || '',
        tx.f_teid_ipv4 || '',
        ...(tx.retransmit_frames || []).map(String),
      ].some(value => value.toLowerCase().includes(normalizedQuery))
    }).sort((left, right) => {
      const rightDuration = right.response_frame ? right.response_time_ms || 0 : -1
      const leftDuration = left.response_frame ? left.response_time_ms || 0 : -1
      if (rightDuration !== leftDuration) return rightDuration - leftDuration
      return left.request_frame - right.request_frame
    })
  }, [result, statusFilter, procedureFilter, responseTimeFilter, query])

  const handleCopy = useCallback(async (id: string, filter: string) => {
    const copied = await copyText(filter)
    if (!copied) return
    setCopiedId(id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const stats = result?.statistics
  const transactionTypes = useMemo(() => {
    if (!result) return []
    return result.procedure_stats || []
  }, [result])
  const pagedTransactions = useMemo(() => paginate(filteredTransactions, transactionPage), [filteredTransactions, transactionPage])

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 overflow-hidden">
      <div className={`${collapsed ? '' : 'border-b'} border-slate-200 bg-white px-5 py-4`}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-orange-50 text-orange-600 flex items-center justify-center border border-orange-100">
              <DatabaseZap className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-900">S11 Message Analyzer</h3>
              <p className="text-xs text-slate-500">
                {collapsed && result ? `S11 ${stats?.total_transactions || 0} 个请求响应事务 · 成功率 ${(stats?.success_rate || 0).toFixed(1)}%` : 'GTPv2-C 请求响应事务 / Cause / TEID 分析'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleAnalyze} disabled={loading} className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all active:scale-[0.98]">
              {loading ? (paused ? <Pause className="w-4 h-4" /> : <Loader2 className="w-4 h-4 animate-spin" />) : result ? <RefreshCw className="w-4 h-4" /> : <Upload className="w-4 h-4" />}
              <span>{loading ? (paused ? '已暂停' : '分析中...') : result ? '重新分析' : '开始分析'}</span>
            </button>
            {loading && (
              <button onClick={handlePauseToggle} className="inline-flex items-center justify-center gap-2 rounded-lg bg-amber-50 px-3 py-2.5 text-sm font-semibold text-amber-700 transition-all hover:bg-amber-100 active:scale-[0.98]">
                {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                <span>{paused ? '继续' : '暂停'}</span>
              </button>
            )}
            <button onClick={() => setCollapsed(value => !value)} className="inline-flex items-center justify-center gap-2 px-3 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm font-semibold rounded-lg transition-all active:scale-[0.98]">
              <ChevronDown className={`w-4 h-4 transition-transform ${collapsed ? '' : 'rotate-180'}`} />
              <span>{collapsed ? '展开' : '收起'}</span>
            </button>
          </div>
        </div>
      </div>

      {!collapsed && (result || error || loading) && (
        <div className="p-6">
          {loading && <StreamProgressBar progress={progress} label={paused ? '已暂停 S11/GTPv2-C 消息分析' : '正在流式分析 S11/GTPv2-C 消息'} />}
          {error && <div className="p-3 bg-red-50 rounded-lg text-red-700 text-sm font-medium">{error}</div>}
          {result && (
            <>
              <div className="mb-6 overflow-hidden rounded-xl border border-orange-200 bg-gradient-to-r from-orange-50 to-slate-50">
                <div className="grid grid-cols-1 gap-4 px-6 py-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
                  <div className="min-w-0">
                    <p className="text-lg font-bold text-orange-800">分析结果</p>
                    <p className="mt-1 min-w-0 text-sm text-slate-600">
                      文件：<span title={result.filename} className="inline-block max-w-full truncate align-bottom font-mono font-semibold text-slate-900 md:max-w-[520px]">{shortFilename(result.filename)}</span>
                    </p>
                  </div>
                  <div className="grid grid-cols-3 gap-6 text-center">
                    <TopMetric label="事务消息" value={stats?.total_messages || 0} />
                    <TopMetric label="事务数" value={stats?.total_transactions || 0} accent="orange" />
                    <TopMetric label="成功率" value={`${(stats?.success_rate || 0).toFixed(1)}%`} accent="emerald" />
                  </div>
                </div>
              </div>

              {result.truncated && (
                <div className="mb-6 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-800">
                  S11/GTPv2-C 消息数量过大，已分析前 {formatCount(result.message_limit || result.total_packets)} 条匹配消息并停止继续读取，避免环境卡死。
                </div>
              )}

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按 S11 请求响应状态统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
                  <FeatureCard active={statusFilter === 'success'} label="成功事务" value={stats?.successful || 0} tone="emerald" icon={<CheckCircle2 className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'success' ? 'all' : 'success'); setTransactionPage(1) }} />
                  <FeatureCard active={statusFilter === 'failed'} label="失败事务" value={stats?.failed || 0} tone="rose" icon={<XCircle className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'failed' ? 'all' : 'failed'); setTransactionPage(1) }} />
                  <FeatureCard active={statusFilter === 'no_response'} label="无响应" value={stats?.no_response || 0} tone="amber" icon={<Clock3 className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'no_response' ? 'all' : 'no_response'); setTransactionPage(1) }} />
                  <FeatureCard active={statusFilter === 'timeout'} label="超时" value={stats?.timeout || 0} tone="orange" icon={<Timer className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'timeout' ? 'all' : 'timeout'); setTransactionPage(1) }} />
                  <FeatureCard active={statusFilter === 'retransmit'} label="重传" value={stats?.retransmit || 0} tone="purple" icon={<RotateCw className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'retransmit' ? 'all' : 'retransmit'); setTransactionPage(1) }} />
                </div>
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按 S11 事务类型统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {transactionTypes.map(item => (
                    <TypeCard key={item.name} active={procedureFilter === item.name} label={item.name} value={item.count} onClick={() => { setProcedureFilter(procedureFilter === item.name ? 'all' : item.name); setTransactionPage(1) }} />
                  ))}
                </div>
              </div>

              <div className="mb-6 rounded-xl border border-slate-200 bg-slate-50 px-6 py-5">
                <p className="mb-4 flex items-center gap-2 text-sm font-bold text-slate-600"><Clock3 className="h-4 w-4" />响应时间统计</p>
                <div className="grid grid-cols-1 gap-5 md:grid-cols-3">
                  <ResponseMetric label="平均响应时间" value={stats?.avg_response_time_ms || 0} />
                  <ResponseMetric active={responseTimeFilter === 'min'} label="最小响应时间" value={stats?.min_response_time_ms || 0} tone="emerald" onClick={() => { setResponseTimeFilter(responseTimeFilter === 'min' ? 'all' : 'min'); setTransactionPage(1) }} />
                  <ResponseMetric active={responseTimeFilter === 'max'} label="最大响应时间" value={stats?.max_response_time_ms || 0} tone="orange" onClick={() => { setResponseTimeFilter(responseTimeFilter === 'max' ? 'all' : 'max'); setTransactionPage(1) }} />
                </div>
              </div>

              <div className="rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-col justify-between gap-3 border-b border-slate-200 bg-white px-4 py-4 lg:flex-row lg:items-center">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">S11 事务列表</p>
                    <span className="text-sm text-slate-500">共 {filteredTransactions.length} 条事务</span>
                    {statusFilter !== 'all' && <FilterPill label={`状态：${statusLabels[statusFilter]}`} />}
                    {procedureFilter !== 'all' && <FilterPill label={`流程：${procedureFilter}`} />}
                    {responseTimeFilter !== 'all' && <FilterPill label={`响应时间：${responseTimeFilter === 'min' ? '最小' : '最大'}`} />}
                    {query.trim() !== '' && <FilterPill label={`搜索：${query.trim()}`} />}
                  </div>
                  <div className="flex flex-col gap-2 md:flex-row md:items-center">
                    {(statusFilter !== 'all' || procedureFilter !== 'all' || responseTimeFilter !== 'all' || query.trim() !== '') && (
                      <button onClick={() => { setStatusFilter('all'); setProcedureFilter('all'); setResponseTimeFilter('all'); setQuery(''); setTransactionPage(1) }} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700">清除筛选</button>
                    )}
                    <label className="relative block md:w-80">
                      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                      <input
                        value={query}
                        onChange={event => { setQuery(event.target.value); setTransactionPage(1) }}
                        className="w-full rounded-lg border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 text-sm focus:border-orange-400 focus:outline-none focus:ring-2 focus:ring-orange-500/30"
                        placeholder="搜索 SEQ / 帧 / Cause / APN / IP"
                      />
                    </label>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">流程</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">状态</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">SEQ</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">请求帧</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">响应帧</th>
                        <th className="px-4 py-3 text-right font-semibold text-orange-700">耗时</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">Cause</th>
                        <th className="px-4 py-3 text-right font-semibold text-orange-700">重传</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">APN</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {pagedTransactions.map(tx => (
                        <tr key={tx.id} onClick={() => setSelectedTransaction(tx)} className="cursor-pointer hover:bg-orange-50/60">
                          <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{tx.procedure}</td>
                          <td className="px-4 py-3"><StatusBadge status={tx.status} /></td>
                          <td className="px-4 py-3 font-mono text-slate-700">{tx.sequence_number}</td>
                          <td className="px-4 py-3 font-mono text-slate-700">{tx.request_frame}</td>
                          <td className="px-4 py-3 font-mono text-slate-700">{tx.response_frame || '-'}</td>
                          <td className="px-4 py-3 text-right font-semibold tabular-nums text-slate-900">{tx.response_frame ? formatDuration(tx.response_time_ms) : '-'}</td>
                          <td className="px-4 py-3 text-slate-700 whitespace-nowrap">{tx.cause_name || '-'}</td>
                          <td className="px-4 py-3 text-right font-semibold tabular-nums text-slate-700">{tx.retransmit_count || '-'}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600">{tx.apn || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredTransactions.length === 0 && <div className="py-8 text-center text-sm text-slate-500">没有匹配的 S11 事务</div>}
                {filteredTransactions.length > 0 && <PaginationControls total={filteredTransactions.length} page={transactionPage} pageSize={PAGE_SIZE} onPageChange={setTransactionPage} />}
              </div>

            </>
          )}
        </div>
      )}

      {selectedTransaction && <TransactionDetailModal transaction={selectedTransaction} copied={copiedId === selectedTransaction.id} onCopy={() => handleCopy(selectedTransaction.id, selectedTransaction.wireshark_filter)} onClose={() => setSelectedTransaction(null)} />}
    </div>
  )
}

function TopMetric({ label, value, accent = 'slate' }: { label: string; value: number | string; accent?: 'slate' | 'orange' | 'emerald' }) {
  const valueClass = accent === 'orange' ? 'text-orange-600' : accent === 'emerald' ? 'text-emerald-600' : 'text-slate-900'
  return <div className="min-w-20"><p className={`text-3xl font-black tabular-nums ${valueClass}`}>{value}</p><p className="mt-1 text-xs font-semibold text-slate-500">{label}</p></div>
}

function ResponseMetric({ active = false, label, value, tone = 'slate', onClick }: { active?: boolean; label: string; value: number; tone?: 'slate' | 'emerald' | 'orange'; onClick?: () => void }) {
  const valueClass = tone === 'emerald' ? 'text-emerald-600' : tone === 'orange' ? 'text-orange-600' : 'text-slate-900'
  const content = <><p className="mb-1 text-sm font-semibold text-slate-500">{label}</p><p className={`text-2xl font-black tabular-nums ${valueClass}`}>{formatDuration(value)}</p></>
  if (!onClick) return <div>{content}</div>
  return <button type="button" onClick={onClick} className={`rounded-xl px-4 py-3 text-left transition-all hover:bg-white hover:shadow-sm ${active ? 'bg-white ring-2 ring-orange-500' : ''}`}>{content}</button>
}

function FeatureCard({ active, label, value, tone, icon, onClick }: { active: boolean; label: string; value: number; tone: string; icon: ReactNode; onClick: () => void }) {
  const toneClasses: Record<string, string> = {
    emerald: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    rose: 'text-rose-600 bg-rose-50 border-rose-200',
    amber: 'text-amber-600 bg-amber-50 border-amber-200',
    orange: 'text-orange-600 bg-orange-50 border-orange-200',
    purple: 'text-purple-600 bg-purple-50 border-purple-200',
  }
  return <button onClick={onClick} className={`min-h-24 rounded-xl border px-5 py-4 text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${toneClasses[tone]} ${active ? 'ring-2 ring-orange-500 ring-offset-2' : ''}`}><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-bold opacity-80">{label}</p><p className="mt-2 text-3xl font-black tabular-nums">{value}</p></div><span className="rounded-lg bg-white/80 p-2 shadow-sm">{icon}</span></div></button>
}

function TypeCard({ active, label, value, onClick }: { active: boolean; label: string; value: number; onClick: () => void }) {
  return <button onClick={onClick} className={`rounded-xl border border-orange-200 bg-orange-50 px-5 py-4 text-left text-orange-600 transition-all hover:-translate-y-0.5 hover:shadow-md ${active ? 'ring-2 ring-orange-500 ring-offset-2' : ''}`}><div className="flex items-start justify-between gap-4"><p className="truncate text-sm font-bold text-slate-700">{label}</p><p className="text-3xl font-black tabular-nums">{value}</p></div></button>
}

function StatusBadge({ status }: { status: TransactionStatus }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${statusClasses[status]}`}>{statusLabels[status]}</span>
}

function FilterPill({ label }: { label: string }) {
  return <span className="rounded-full border border-orange-200 bg-orange-50 px-3 py-1 text-xs font-bold text-orange-700">{label}</span>
}

function TransactionDetailModal({ transaction, copied, onCopy, onClose }: { transaction: S11Transaction; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <ModalHeader title="S11 事务详情" subtitle={`${transaction.procedure} · SEQ ${transaction.sequence_number}`} onClose={onClose} />
        <div className="space-y-5 p-6">
          <div className="rounded-xl border border-orange-200 bg-orange-50 px-5 py-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-bold text-orange-700">{transaction.request_type}</p><p className="mt-1 text-2xl font-black text-slate-900">{transaction.response_type || 'No Response'}</p></div><StatusBadge status={transaction.status} /></div></div>
          <DetailSection icon={<Clock3 className="h-4 w-4" />} title="时间信息"><div className="grid grid-cols-1 gap-3 md:grid-cols-3"><DetailValue label="请求时间" value={formatTimestamp(transaction.request_time)} /><DetailValue label="响应时间" value={transaction.response_time ? formatTimestamp(transaction.response_time) : '-'} /><DetailValue label="耗时" value={transaction.response_frame ? formatDuration(transaction.response_time_ms) : '-'} /></div></DetailSection>
          <DetailSection icon={<Activity className="h-4 w-4" />} title="隧道与结果"><div className="grid grid-cols-1 gap-3 md:grid-cols-2"><DetailValue label="请求 TEID" value={transaction.request_teid || '-'} /><DetailValue label="响应 TEID" value={transaction.response_teid || '-'} /><DetailValue label="Cause" value={`${transaction.cause || '-'} ${transaction.cause_name || ''}`} /><DetailValue label="重传帧" value={transaction.retransmit_frames?.length ? transaction.retransmit_frames.join(', ') : '-'} /><DetailValue label="APN" value={transaction.apn || '-'} /><DetailValue label="F-TEID IPv4" value={transaction.f_teid_ipv4 || '-'} /></div></DetailSection>
          <FilterCopy filter={transaction.wireshark_filter} copied={copied} onCopy={onCopy} />
        </div>
      </div>
    </div>
  )
}

function ModalHeader({ title, subtitle, onClose }: { title: string; subtitle: string; onClose: () => void }) {
  return <div className="flex items-start justify-between border-b border-slate-200 px-6 py-5"><div className="flex items-center gap-3"><div className="rounded-full bg-orange-50 p-2 text-orange-600"><DatabaseZap className="h-5 w-5" /></div><div><h4 className="text-xl font-bold text-slate-900">{title}</h4><p className="mt-1 text-sm font-mono text-slate-500">{subtitle}</p></div></div><button onClick={onClose} className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700"><X className="h-5 w-5" /></button></div>
}

function DetailSection({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return <section><p className="mb-3 flex items-center gap-2 text-sm font-bold text-slate-600">{icon}<span>{title}</span></p><div className="rounded-xl bg-slate-50 p-4">{children}</div></section>
}

function DetailValue({ label, value }: { label: string; value: string | number }) {
  return <div><p className="mb-1 text-xs font-semibold text-slate-500">{label}</p><p className="break-all font-mono text-sm font-bold text-slate-900">{value}</p></div>
}

function FilterCopy({ filter, copied, onCopy }: { filter: string; copied: boolean; onCopy: () => void }) {
  return <DetailSection icon={<Copy className="h-4 w-4" />} title="Wireshark 过滤器"><div className="flex items-center justify-between gap-3 rounded-lg bg-slate-100 px-4 py-3 font-mono text-xs text-slate-700"><span className="break-all">{filter}</span><button type="button" onClick={event => { event.preventDefault(); event.stopPropagation(); onCopy() }} className="shrink-0 rounded-md bg-white px-2 py-1 font-sans text-xs font-bold text-orange-600 shadow-sm hover:bg-orange-50 active:scale-95">{copied ? '已复制' : '复制'}</button></div></DetailSection>
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

function sameResponseTime(value: number | undefined, target: number): boolean {
  if (value == null) return false
  return Math.abs(value - target) < 0.000001
}

function paginate<T>(items: T[], page: number) {
  const pageCount = Math.max(1, Math.ceil(items.length / PAGE_SIZE))
  const safePage = Math.min(Math.max(page, 1), pageCount)
  const start = (safePage - 1) * PAGE_SIZE
  return items.slice(start, start + PAGE_SIZE)
}

function shortFilename(filename?: string) {
  if (!filename) return '当前上传抓包'
  const parts = filename.split(/[\\/]/)
  return parts[parts.length - 1] || filename
}

function formatCount(value: number) {
  return new Intl.NumberFormat('zh-CN').format(value)
}
