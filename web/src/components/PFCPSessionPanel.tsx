import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, AlertTriangle, CheckCircle2, ChevronDown, Clock3, Copy, Loader2, RefreshCw, Search, Upload, X, XCircle, Zap } from 'lucide-react'
import { copyText } from '../utils/clipboard'

interface PFCPSessionPanelProps {
  jobId: string
}

type SessionStatus = 'success' | 'failed' | 'no_response' | 'timeout' | 'retransmit'
type SessionMessageType = 'Session Establishment' | 'Session Modification' | 'Session Deletion'
type ResponseTimeFilter = 'all' | 'min' | 'max'

interface PFCPSessionStatistics {
  total_transactions: number
  success: number
  failed: number
  no_response: number
  timeout: number
  retransmit: number
  session_establishment: number
  session_modification: number
  session_deletion: number
  avg_response_time_ms: number
  max_response_time_ms: number
  min_response_time_ms: number
}

interface PFCPSessionTransaction {
  id: string
  request_seid: number
  response_seid: number
  request_fseid: number
  response_fseid: number
  sequence_number: number
  message_type: string
  message_type_code: number
  status: SessionStatus
  cause?: number
  cause_name?: string
  source_ip: string
  destination_ip: string
  request_time: string
  response_time?: string
  response_time_ms?: number
  request_frame: number
  response_frame?: number
  retransmit_count: number
  retransmit_frames?: number[]
  wireshark_filter: string
}

interface PFCPSessionResult {
  filename: string
  analyzed_at: string
  total_packets: number
  statistics: PFCPSessionStatistics
  transactions: PFCPSessionTransaction[]
}

interface APIResponse<T> {
  success: boolean
  data?: T
  error?: string
}

const statusLabels: Record<SessionStatus, string> = {
  success: '成功',
  failed: '失败',
  no_response: '无响应',
  timeout: '超时',
  retransmit: '重传',
}

const statusClasses: Record<SessionStatus, string> = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  failed: 'bg-rose-50 text-rose-700 border-rose-200',
  no_response: 'bg-slate-100 text-slate-700 border-slate-200',
  timeout: 'bg-amber-50 text-amber-700 border-amber-200',
  retransmit: 'bg-violet-50 text-violet-700 border-violet-200',
}

const messageTypeLabels: Record<SessionMessageType, string> = {
  'Session Establishment': 'Session Establishment',
  'Session Modification': 'Session Modification',
  'Session Deletion': 'Session Deletion',
}

export function PFCPSessionPanel({ jobId }: PFCPSessionPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<PFCPSessionResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<'all' | SessionStatus>('all')
  const [messageTypeFilter, setMessageTypeFilter] = useState<'all' | SessionMessageType>('all')
  const [responseTimeFilter, setResponseTimeFilter] = useState<ResponseTimeFilter>('all')
  const [query, setQuery] = useState('')
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [selectedTransaction, setSelectedTransaction] = useState<PFCPSessionTransaction | null>(null)
  const [collapsed, setCollapsed] = useState(false)

  const handleAnalyze = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`/api/jobs/${jobId}/pfcp-sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ timeout_seconds: 3, limit: 500 }),
      })
      const data = (await response.json()) as APIResponse<PFCPSessionResult>
      if (!data.success || !data.data) {
        throw new Error(data.error || 'PFCP会话分析失败')
      }
      setResult(data.data)
      setStatusFilter('all')
      setMessageTypeFilter('all')
      setResponseTimeFilter('all')
      setSelectedTransaction(null)
      setQuery('')
    } catch (err) {
      setError('PFCP会话分析失败: ' + (err as Error).message)
    } finally {
      setLoading(false)
    }
  }, [jobId])

  const filteredTransactions = useMemo(() => {
    if (!result) return []
    const transactions = result.transactions || []
    const normalizedQuery = query.trim().toLowerCase()
    const targetResponseTime = responseTimeFilter === 'min'
      ? result.statistics.min_response_time_ms
      : responseTimeFilter === 'max'
        ? result.statistics.max_response_time_ms
        : null

    return transactions.filter(tx => {
      if (statusFilter === 'retransmit' && (tx.retransmit_count || 0) <= 0) return false
      if (statusFilter !== 'all' && statusFilter !== 'retransmit' && tx.status !== statusFilter) return false
      if (messageTypeFilter !== 'all' && tx.message_type !== messageTypeFilter) return false
      if (targetResponseTime != null && !sameResponseTime(tx.response_time_ms, targetResponseTime)) return false
      if (!normalizedQuery) return true
      return [
        tx.id,
        tx.message_type,
        tx.source_ip,
        tx.destination_ip,
        String(tx.sequence_number),
        String(tx.request_seid),
        String(tx.response_seid),
        String(tx.request_frame),
        tx.cause_name || '',
      ].some(value => value.toLowerCase().includes(normalizedQuery))
    }).sort((left, right) => {
      const rightDuration = right.response_time_ms ?? -1
      const leftDuration = left.response_time_ms ?? -1
      if (rightDuration !== leftDuration) return rightDuration - leftDuration
      return left.request_frame - right.request_frame
    })
  }, [result, statusFilter, messageTypeFilter, responseTimeFilter, query])

  const handleCopyFilter = useCallback(async (tx: PFCPSessionTransaction) => {
    const copied = await copyText(tx.wireshark_filter)
    if (!copied) return
    setCopiedId(tx.id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const stats = result?.statistics
  const successRate = stats && stats.total_transactions > 0 ? (stats.success / stats.total_transactions) * 100 : 0

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 overflow-hidden">
      <div className={`${collapsed ? '' : 'border-b'} border-slate-200 bg-white px-5 py-4`}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-50 text-cyan-600 flex items-center justify-center border border-cyan-100">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-900">PFCP Session Analyzer</h3>
              <p className="text-xs text-slate-500">
                {collapsed && result ? `事务 ${stats?.total_transactions || 0} · 成功率 ${successRate.toFixed(1)}%` : 'PFCP 会话事务状态分析'}
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
          <div className="rounded-xl border border-cyan-100 bg-cyan-50 px-5 py-4 text-sm font-semibold text-cyan-700">
            正在分析 PFCP 会话事务...
          </div>
        )}

        {error && (
          <div className="p-3 bg-red-50 rounded-lg text-red-700 text-sm font-medium">
            {error}
          </div>
        )}

        {result && (
          <>
            <div className="mb-6 overflow-hidden rounded-xl border border-cyan-200 bg-gradient-to-r from-cyan-50 to-slate-50">
              <div className="grid grid-cols-1 gap-4 px-6 py-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
                <div className="min-w-0">
                  <p className="text-lg font-bold text-cyan-800">分析结果</p>
                  <p className="mt-1 min-w-0 text-sm text-slate-600">
                    文件：<span title={result.filename} className="inline-block max-w-full truncate align-bottom font-mono font-semibold text-slate-900 md:max-w-[520px]">{shortFilename(result.filename) || '当前上传抓包'}</span>
                  </p>
                </div>

                <div className="grid grid-cols-3 gap-6 text-center">
                  <TopMetric label="总事务数" value={stats?.total_transactions || 0} />
                  <TopMetric label="PFCP 包数" value={result.total_packets || 0} accent="cyan" />
                  <TopMetric label="成功率" value={`${successRate.toFixed(1)}%`} accent="emerald" />
                </div>
              </div>
            </div>

            <div className="mb-6">
              <p className="mb-3 text-sm font-bold text-slate-600">按状态统计</p>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
                <StatusCard active={statusFilter === 'success'} label="成功" value={stats?.success || 0} tone="emerald" icon={<CheckCircle2 className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'success' ? 'all' : 'success')} />
                <StatusCard active={statusFilter === 'failed'} label="失败" value={stats?.failed || 0} tone="rose" icon={<XCircle className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'failed' ? 'all' : 'failed')} />
                <StatusCard active={statusFilter === 'no_response'} label="无响应" value={stats?.no_response || 0} tone="slate" icon={<AlertTriangle className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'no_response' ? 'all' : 'no_response')} />
                <StatusCard active={statusFilter === 'timeout'} label="超时" value={stats?.timeout || 0} tone="amber" icon={<Clock3 className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'timeout' ? 'all' : 'timeout')} />
                <StatusCard active={statusFilter === 'retransmit'} label="重传" value={stats?.retransmit || 0} tone="violet" icon={<RefreshCw className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'retransmit' ? 'all' : 'retransmit')} />
              </div>
            </div>

            <div className="mb-6">
              <p className="mb-3 text-sm font-bold text-slate-600">按消息类型统计</p>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                <TypeCard
                  active={messageTypeFilter === 'Session Establishment'}
                  label="Session Establishment"
                  value={stats?.session_establishment || 0}
                  icon={<Zap className="w-5 h-5" />}
                  tone="cyan"
                  onClick={() => setMessageTypeFilter(messageTypeFilter === 'Session Establishment' ? 'all' : 'Session Establishment')}
                />
                <TypeCard
                  active={messageTypeFilter === 'Session Modification'}
                  label="Session Modification"
                  value={stats?.session_modification || 0}
                  icon={<Activity className="w-5 h-5" />}
                  tone="indigo"
                  onClick={() => setMessageTypeFilter(messageTypeFilter === 'Session Modification' ? 'all' : 'Session Modification')}
                />
                <TypeCard
                  active={messageTypeFilter === 'Session Deletion'}
                  label="Session Deletion"
                  value={stats?.session_deletion || 0}
                  icon={<XCircle className="w-5 h-5" />}
                  tone="rose"
                  onClick={() => setMessageTypeFilter(messageTypeFilter === 'Session Deletion' ? 'all' : 'Session Deletion')}
                />
              </div>
            </div>

            <div className="mb-8 rounded-xl border border-slate-200 bg-slate-50 px-6 py-5">
              <p className="mb-4 flex items-center gap-2 text-sm font-bold text-slate-700">
                <Clock3 className="w-4 h-4 text-slate-500" />
                <span>响应时间统计</span>
              </p>
              <div className="grid grid-cols-1 gap-5 md:grid-cols-3">
                <ResponseMetric label="平均响应时间" value={formatMs(stats?.avg_response_time_ms)} tone="slate" />
                <ResponseMetric
                  active={responseTimeFilter === 'min'}
                  label="最小响应时间"
                  value={formatMs(stats?.min_response_time_ms)}
                  tone="emerald"
                  onClick={() => setResponseTimeFilter(responseTimeFilter === 'min' ? 'all' : 'min')}
                />
                <ResponseMetric
                  active={responseTimeFilter === 'max'}
                  label="最大响应时间"
                  value={formatMs(stats?.max_response_time_ms)}
                  tone="amber"
                  onClick={() => setResponseTimeFilter(responseTimeFilter === 'max' ? 'all' : 'max')}
                />
              </div>
            </div>

          <div className="animate-fade-in rounded-xl border border-slate-200 overflow-hidden">
            <div className="flex flex-col gap-3 border-b border-slate-200 bg-white px-4 py-4 md:flex-row md:items-center md:justify-between">
              <div className="flex flex-wrap items-center gap-3">
                <p className="text-base font-bold text-slate-900">会话列表</p>
                <span className="text-sm text-slate-500">共 {filteredTransactions.length} 条记录</span>
                {statusFilter !== 'all' && (
                  <span className="rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 text-xs font-bold text-cyan-700">
                    状态：{statusLabels[statusFilter]}
                  </span>
                )}
                {messageTypeFilter !== 'all' && (
                  <span className="rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 text-xs font-bold text-indigo-700">
                    类型：{messageTypeLabels[messageTypeFilter]}
                  </span>
                )}
                {responseTimeFilter !== 'all' && (
                  <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-bold text-amber-700">
                    响应时间：{responseTimeFilter === 'min' ? '最小' : '最大'}
                  </span>
                )}
                {(statusFilter !== 'all' || messageTypeFilter !== 'all' || responseTimeFilter !== 'all') && (
                  <button
                    onClick={() => {
                      setStatusFilter('all')
                      setMessageTypeFilter('all')
                      setResponseTimeFilter('all')
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
                  placeholder="搜索 IP / SEID / 序列号"
                />
              </label>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">SEQ NO</th>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">请求 SEID</th>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">响应 SEID</th>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">消息类型</th>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">源 IP</th>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">目的 IP</th>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">状态</th>
                    <th className="px-4 py-3 text-right font-semibold text-cyan-700">响应时间</th>
                    <th className="px-4 py-3 text-left font-semibold text-cyan-700">重传</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 bg-white">
                  {filteredTransactions.map(tx => (
                    <tr
                      key={tx.id}
                      onClick={() => setSelectedTransaction(tx)}
                      className="cursor-pointer hover:bg-cyan-50/60"
                    >
                      <td className="px-4 py-3 font-mono text-slate-700">{tx.sequence_number}</td>
                      <td className="px-4 py-3"><Seid value={tx.request_seid} /></td>
                      <td className="px-4 py-3"><Seid value={tx.response_seid || tx.response_fseid} /></td>
                      <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{tx.message_type}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-600 whitespace-nowrap">{tx.source_ip}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-600 whitespace-nowrap">{tx.destination_ip}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${statusClasses[tx.status]}`}>
                          {statusLabels[tx.status]}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right tabular-nums font-semibold text-slate-900">
                        {tx.response_time_ms == null ? '-' : formatMs(tx.response_time_ms)}
                      </td>
                      <td className="px-4 py-3 text-slate-500">{tx.retransmit_count > 0 ? tx.retransmit_count : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {filteredTransactions.length === 0 && (
              <div className="py-8 text-center text-sm text-slate-500">
                没有匹配的PFCP会话事务
              </div>
            )}
          </div>
          </>
        )}
        </div>
      )}

      {selectedTransaction && (
        <TransactionDetailModal
          transaction={selectedTransaction}
          copied={copiedId === selectedTransaction.id}
          onCopy={() => handleCopyFilter(selectedTransaction)}
          onClose={() => setSelectedTransaction(null)}
        />
      )}
    </div>
  )
}

function TopMetric({ label, value, accent = 'slate' }: { label: string; value: number | string; accent?: 'slate' | 'cyan' | 'emerald' }) {
  const valueClass = accent === 'emerald' ? 'text-emerald-600' : accent === 'cyan' ? 'text-cyan-600' : 'text-slate-900'
  return (
    <div className="min-w-20">
      <p className={`text-3xl font-black tabular-nums ${valueClass}`}>{value}</p>
      <p className="mt-1 text-xs font-semibold text-slate-500"> {label}</p>
    </div>
  )
}

function StatusCard({ active, label, value, tone, icon, onClick }: { active: boolean; label: string; value: number; tone: string; icon: ReactNode; onClick: () => void }) {
  const toneClasses: Record<string, string> = {
    emerald: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    rose: 'text-rose-600 bg-rose-50 border-rose-200',
    slate: 'text-slate-600 bg-slate-50 border-slate-200',
    amber: 'text-amber-600 bg-amber-50 border-amber-200',
    violet: 'text-violet-600 bg-violet-50 border-violet-200',
  }

  return (
    <button
      onClick={onClick}
      className={`min-h-24 rounded-xl border px-5 py-4 text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${toneClasses[tone]} ${active ? 'ring-2 ring-cyan-500 ring-offset-2' : ''}`}
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

function TypeCard({ active, label, value, tone, icon, onClick }: { active: boolean; label: string; value: number; tone: 'cyan' | 'indigo' | 'rose'; icon: ReactNode; onClick: () => void }) {
  const classes = {
    cyan: 'text-cyan-600 bg-cyan-50 border-cyan-200',
    indigo: 'text-indigo-600 bg-indigo-50 border-indigo-200',
    rose: 'text-rose-600 bg-rose-50 border-rose-200',
  }
  return (
    <button
      onClick={onClick}
      className={`rounded-xl border px-5 py-5 text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${classes[tone]} ${active ? 'ring-2 ring-indigo-500 ring-offset-2' : ''}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-bold text-slate-600">{label}</p>
          <p className="mt-2 text-3xl font-black tabular-nums">{value}</p>
        </div>
        <span className="rounded-lg bg-white/80 p-2 shadow-sm">{icon}</span>
      </div>
    </button>
  )
}

function ResponseMetric({ active = false, label, value, tone, onClick }: { active?: boolean; label: string; value: string; tone: 'slate' | 'emerald' | 'amber'; onClick?: () => void }) {
  const valueClass = tone === 'emerald' ? 'text-emerald-600' : tone === 'amber' ? 'text-amber-600' : 'text-slate-900'
  const content = (
    <>
      <p className="text-sm font-semibold text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-black tabular-nums ${valueClass}`}>{value}</p>
    </>
  )

  if (!onClick) {
    return <div>{content}</div>
  }

  return (
    <button
      onClick={onClick}
      className={`rounded-lg px-3 py-2 text-left transition-all hover:bg-white hover:shadow-sm ${active ? 'bg-white ring-2 ring-cyan-500 ring-offset-2' : ''}`}
    >
      {content}
    </button>
  )
}

function TransactionDetailModal({ transaction, copied, onCopy, onClose }: { transaction: PFCPSessionTransaction; copied: boolean; onCopy: () => void; onClose: () => void }) {
  const responseTime = transaction.response_time_ms == null ? '-' : formatMs(transaction.response_time_ms)

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/45 px-4 py-8 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-3xl overflow-hidden rounded-2xl bg-white shadow-2xl shadow-slate-950/20">
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-5">
          <div className="flex items-start gap-3">
            <div className={`mt-0.5 rounded-full border p-1.5 ${statusClasses[transaction.status]}`}>
              {transaction.status === 'success' ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
            </div>
            <div>
              <h4 className="text-xl font-bold text-slate-900">会话详情</h4>
              <p className="mt-1 text-sm text-slate-500">
                {transaction.message_type} · Seq {transaction.sequence_number}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
            aria-label="关闭"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="max-h-[calc(90vh-5rem)] overflow-y-auto px-6 py-6">
          <div className={`mb-6 rounded-xl border px-5 py-4 ${statusClasses[transaction.status]}`}>
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-lg font-bold">{statusLabels[transaction.status]}</p>
                <p className="mt-1 text-sm opacity-80">
                  Cause: {transaction.cause == null ? '-' : transaction.cause} {transaction.cause_name ? `- ${transaction.cause_name}` : ''}
                </p>
              </div>
              <div className="text-left md:text-right">
                <p className="text-2xl font-black tabular-nums">{responseTime}</p>
                <p className="text-xs font-semibold opacity-70">响应时间</p>
              </div>
            </div>
          </div>

          <DetailSection title="SEID 信息">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <DetailValue label="请求头部 SEID" value={<Seid value={transaction.request_seid} />} />
              <DetailValue label="请求 F-SEID" value={<Seid value={transaction.request_fseid} />} />
              <DetailValue label="响应头部 SEID" value={<Seid value={transaction.response_seid} />} />
              <DetailValue label="响应 F-SEID" value={<Seid value={transaction.response_fseid} />} />
            </div>
          </DetailSection>

          <DetailSection title="网络信息">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-[1fr_auto_1fr] md:items-center">
              <DetailValue label="源地址" value={<span className="font-mono text-lg font-bold text-slate-900">{transaction.source_ip}</span>} />
              <div className="hidden text-cyan-600 md:block">-&gt;</div>
              <DetailValue label="目的地址" value={<span className="font-mono text-lg font-bold text-slate-900">{transaction.destination_ip}</span>} />
            </div>
          </DetailSection>

          <DetailSection title="时间信息">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <DetailValue label="请求帧" value={<span className="font-mono font-bold text-slate-900">{transaction.request_frame}</span>} />
              <DetailValue label="响应帧" value={<span className="font-mono font-bold text-slate-900">{transaction.response_frame || '-'}</span>} />
              <DetailValue label="重传次数" value={<span className="font-mono font-bold text-slate-900">{transaction.retransmit_count || 0}</span>} />
            </div>
          </DetailSection>

          <DetailSection title="Wireshark 过滤器">
            <div className="flex w-full items-start gap-2 rounded-lg bg-slate-950 px-4 py-3 text-cyan-200">
              <Copy className="mt-0.5 h-4 w-4 flex-shrink-0" />
              <code className="min-w-0 flex-1 break-all text-xs leading-5">{transaction.wireshark_filter}</code>
              <button type="button" onClick={event => { event.preventDefault(); event.stopPropagation(); onCopy() }} className="shrink-0 rounded-md bg-white/10 px-2 py-1 text-xs font-bold text-cyan-100 hover:bg-white/20 active:scale-95">{copied ? '已复制' : '复制'}</button>
            </div>
          </DetailSection>
        </div>
      </div>
    </div>
  )
}

function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mb-6 last:mb-0">
      <h5 className="mb-3 text-sm font-bold text-slate-700">{title}</h5>
      <div className="rounded-xl bg-slate-50 p-4">{children}</div>
    </section>
  )
}

function DetailValue({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <p className="mb-2 text-xs font-semibold text-slate-500">{label}</p>
      <div className="min-h-9 rounded-lg bg-white px-3 py-2 shadow-sm shadow-slate-900/5">{value}</div>
    </div>
  )
}

function Seid({ value }: { value: number }) {
  if (!value) return <span className="text-slate-300">-</span>
  return (
    <code className="rounded-md bg-cyan-50 px-2 py-1 text-xs font-semibold text-cyan-700">
      0x{value.toString(16).toUpperCase().padStart(16, '0')}
    </code>
  )
}

function shortFilename(filename?: string): string {
  if (!filename) return ''
  const parts = filename.split(/[\\/]/)
  return parts[parts.length - 1] || filename
}

function formatMs(value?: number): string {
  if (value == null) return '0 ms'
  if (value >= 1000) return `${(value / 1000).toFixed(2)} s`
  return `${value.toFixed(value >= 10 ? 1 : 2)} ms`
}

function sameResponseTime(value: number | undefined, target: number): boolean {
  if (value == null) return false
  return Math.abs(value - target) < 0.000001
}
