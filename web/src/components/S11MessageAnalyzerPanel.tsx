import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, CheckCircle2, ChevronDown, Clock3, Copy, DatabaseZap, Loader2, RefreshCw, Search, Upload, X, XCircle } from 'lucide-react'

interface S11MessageAnalyzerPanelProps {
  jobId: string
}

type TransactionStatus = 'success' | 'failed' | 'no_response'

interface S11Statistics {
  total_messages: number
  requests: number
  responses: number
  total_transactions: number
  successful: number
  failed: number
  no_response: number
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
  wireshark_filter: string
}

interface S11Message {
  id: string
  frame_number: number
  timestamp: string
  source_ip: string
  destination_ip: string
  message_type_code: number
  message_type: string
  sequence_number: number
  teid?: string
  cause?: string
  cause_name?: string
  apn?: string
  f_teid_ipv4?: string
  wireshark_filter: string
}

interface TypeCount {
  code: number
  name: string
  count: number
}

interface ProcedureCount {
  name: string
  count: number
}

interface S11AnalysisResult {
  filename: string
  analyzed_at: string
  total_packets: number
  statistics: S11Statistics
  messages: S11Message[]
  type_stats: TypeCount[]
  transactions: S11Transaction[]
  procedure_stats: ProcedureCount[]
}

interface APIResponse<T> {
  success: boolean
  data?: T
  error?: string
}

const statusLabels: Record<TransactionStatus, string> = {
  success: '成功',
  failed: '失败',
  no_response: '无响应',
}

const statusClasses: Record<TransactionStatus, string> = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  failed: 'bg-rose-50 text-rose-700 border-rose-200',
  no_response: 'bg-amber-50 text-amber-700 border-amber-200',
}

export function S11MessageAnalyzerPanel({ jobId }: S11MessageAnalyzerPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<S11AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [statusFilter, setStatusFilter] = useState<'all' | TransactionStatus>('all')
  const [procedureFilter, setProcedureFilter] = useState<string>('all')
  const [typeFilter, setTypeFilter] = useState<number | 'all'>('all')
  const [query, setQuery] = useState('')
  const [selectedTransaction, setSelectedTransaction] = useState<S11Transaction | null>(null)
  const [selectedMessage, setSelectedMessage] = useState<S11Message | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const handleAnalyze = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(`/api/jobs/${jobId}/s11-messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      const data = (await response.json()) as APIResponse<S11AnalysisResult>
      if (!data.success || !data.data) throw new Error(data.error || 'S11消息分析失败')
      setResult(data.data)
      setStatusFilter('all')
      setProcedureFilter('all')
      setTypeFilter('all')
      setQuery('')
      setSelectedTransaction(null)
      setSelectedMessage(null)
    } catch (err) {
      setError('S11消息分析失败: ' + (err as Error).message)
    } finally {
      setLoading(false)
    }
  }, [jobId])

  const filteredTransactions = useMemo(() => {
    if (!result) return []
    return result.transactions.filter(tx => {
      if (statusFilter !== 'all' && tx.status !== statusFilter) return false
      if (procedureFilter !== 'all' && tx.procedure !== procedureFilter) return false
      return true
    })
  }, [result, statusFilter, procedureFilter])

  const filteredMessages = useMemo(() => {
    if (!result) return []
    const normalizedQuery = query.trim().toLowerCase()
    return result.messages.filter(message => {
      if (typeFilter !== 'all' && message.message_type_code !== typeFilter) return false
      if (!normalizedQuery) return true
      return [
        message.message_type,
        String(message.message_type_code),
        String(message.sequence_number),
        message.source_ip,
        message.destination_ip,
        message.teid || '',
        message.cause_name || '',
        message.apn || '',
      ].some(value => value.toLowerCase().includes(normalizedQuery))
    })
  }, [result, typeFilter, query])

  const handleCopy = useCallback(async (id: string, filter: string) => {
    await navigator.clipboard.writeText(filter)
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
            <div className="w-9 h-9 rounded-xl bg-orange-50 text-orange-600 flex items-center justify-center border border-orange-100">
              <DatabaseZap className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-900">S11 Message Analyzer</h3>
              <p className="text-xs text-slate-500">
                {collapsed && result ? `S11 ${stats?.total_messages || 0} · 成功率 ${(stats?.success_rate || 0).toFixed(1)}%` : 'GTPv2-C 事务 / Cause / TEID 分析'}
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
          {loading && !result && <div className="rounded-xl border border-orange-100 bg-orange-50 px-5 py-4 text-sm font-semibold text-orange-700">正在分析 S11/GTPv2-C 消息...</div>}
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
                    <TopMetric label="S11消息" value={stats?.total_messages || 0} />
                    <TopMetric label="事务数" value={stats?.total_transactions || 0} accent="orange" />
                    <TopMetric label="成功率" value={`${(stats?.success_rate || 0).toFixed(1)}%`} accent="emerald" />
                  </div>
                </div>
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按 S11 事务状态统计</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <FeatureCard active={statusFilter === 'success'} label="成功事务" value={stats?.successful || 0} tone="emerald" icon={<CheckCircle2 className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'success' ? 'all' : 'success')} />
                  <FeatureCard active={statusFilter === 'failed'} label="失败事务" value={stats?.failed || 0} tone="rose" icon={<XCircle className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'failed' ? 'all' : 'failed')} />
                  <FeatureCard active={statusFilter === 'no_response'} label="无响应" value={stats?.no_response || 0} tone="amber" icon={<Clock3 className="w-5 h-5" />} onClick={() => setStatusFilter(statusFilter === 'no_response' ? 'all' : 'no_response')} />
                </div>
              </div>

              <div className="mb-6 rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-4">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">S11 事务列表</p>
                    <span className="text-sm text-slate-500">共 {filteredTransactions.length} 条事务</span>
                    {statusFilter !== 'all' && <FilterPill label={`状态：${statusLabels[statusFilter]}`} />}
                    {procedureFilter !== 'all' && <FilterPill label={`流程：${procedureFilter}`} />}
                  </div>
                  {(statusFilter !== 'all' || procedureFilter !== 'all') && (
                    <button onClick={() => { setStatusFilter('all'); setProcedureFilter('all') }} className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700">清除筛选</button>
                  )}
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
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">APN</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {filteredTransactions.map(tx => (
                        <tr key={tx.id} onClick={() => setSelectedTransaction(tx)} className="cursor-pointer hover:bg-orange-50/60">
                          <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{tx.procedure}</td>
                          <td className="px-4 py-3"><StatusBadge status={tx.status} /></td>
                          <td className="px-4 py-3 font-mono text-slate-700">{tx.sequence_number}</td>
                          <td className="px-4 py-3 font-mono text-slate-700">{tx.request_frame}</td>
                          <td className="px-4 py-3 font-mono text-slate-700">{tx.response_frame || '-'}</td>
                          <td className="px-4 py-3 text-right font-semibold tabular-nums text-slate-900">{tx.response_frame ? formatDuration(tx.response_time_ms) : '-'}</td>
                          <td className="px-4 py-3 text-slate-700 whitespace-nowrap">{tx.cause_name || '-'}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600">{tx.apn || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredTransactions.length === 0 && <div className="py-8 text-center text-sm text-slate-500">没有匹配的 S11 事务</div>}
              </div>

              <div className="mb-6">
                <p className="mb-3 text-sm font-bold text-slate-600">按消息类型统计（筛选消息列表）</p>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {topTypes.map(item => (
                    <TypeCard key={item.code} active={typeFilter === item.code} label={item.name} code={`Type ${item.code}`} value={item.count} onClick={() => setTypeFilter(typeFilter === item.code ? 'all' : item.code)} />
                  ))}
                </div>
              </div>

              <div className="animate-fade-in rounded-xl border border-slate-200 overflow-hidden">
                <div className="flex flex-col gap-3 border-b border-slate-200 bg-white px-4 py-4 md:flex-row md:items-center md:justify-between">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="text-base font-bold text-slate-900">S11 消息列表</p>
                    <span className="text-sm text-slate-500">共 {filteredMessages.length} 条记录</span>
                    {typeFilter !== 'all' && <FilterPill label={`Type：${typeFilter}`} />}
                  </div>
                  <div className="flex flex-col gap-2 md:flex-row md:items-center">
                    {(typeFilter !== 'all' || query.trim() !== '') && <button onClick={() => { setTypeFilter('all'); setQuery('') }} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700">清除消息筛选</button>}
                    <label className="relative block md:w-72">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                      <input value={query} onChange={event => setQuery(event.target.value)} className="w-full rounded-lg border border-slate-200 bg-slate-50 pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-400" placeholder="搜索 IP / SEQ / TEID / APN" />
                    </label>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-sm">
                    <thead className="bg-slate-50">
                      <tr>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">Frame</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">消息类型</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">SEQ</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">源 IP</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">目的 IP</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">TEID</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">Cause</th>
                        <th className="px-4 py-3 text-left font-semibold text-orange-700">APN</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {filteredMessages.map(message => (
                        <tr key={message.id} onClick={() => setSelectedMessage(message)} className="cursor-pointer hover:bg-orange-50/60">
                          <td className="px-4 py-3 font-mono text-slate-700">{message.frame_number}</td>
                          <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{message.message_type}</td>
                          <td className="px-4 py-3 font-mono text-slate-700">{message.sequence_number}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600 whitespace-nowrap">{message.source_ip}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600 whitespace-nowrap">{message.destination_ip}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600">{message.teid || '-'}</td>
                          <td className="px-4 py-3 text-slate-700 whitespace-nowrap">{message.cause_name || '-'}</td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-600">{message.apn || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {filteredMessages.length === 0 && <div className="py-8 text-center text-sm text-slate-500">没有匹配的 S11 消息</div>}
              </div>
            </>
          )}
        </div>
      )}

      {selectedTransaction && <TransactionDetailModal transaction={selectedTransaction} copied={copiedId === selectedTransaction.id} onCopy={() => handleCopy(selectedTransaction.id, selectedTransaction.wireshark_filter)} onClose={() => setSelectedTransaction(null)} />}
      {selectedMessage && <MessageDetailModal message={selectedMessage} copied={copiedId === selectedMessage.id} onCopy={() => handleCopy(selectedMessage.id, selectedMessage.wireshark_filter)} onClose={() => setSelectedMessage(null)} />}
    </div>
  )
}

function TopMetric({ label, value, accent = 'slate' }: { label: string; value: number | string; accent?: 'slate' | 'orange' | 'emerald' }) {
  const valueClass = accent === 'orange' ? 'text-orange-600' : accent === 'emerald' ? 'text-emerald-600' : 'text-slate-900'
  return <div className="min-w-20"><p className={`text-3xl font-black tabular-nums ${valueClass}`}>{value}</p><p className="mt-1 text-xs font-semibold text-slate-500">{label}</p></div>
}

function FeatureCard({ active, label, value, tone, icon, onClick }: { active: boolean; label: string; value: number; tone: string; icon: ReactNode; onClick: () => void }) {
  const toneClasses: Record<string, string> = {
    emerald: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    rose: 'text-rose-600 bg-rose-50 border-rose-200',
    amber: 'text-amber-600 bg-amber-50 border-amber-200',
  }
  return <button onClick={onClick} className={`min-h-24 rounded-xl border px-5 py-4 text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${toneClasses[tone]} ${active ? 'ring-2 ring-orange-500 ring-offset-2' : ''}`}><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-bold opacity-80">{label}</p><p className="mt-2 text-3xl font-black tabular-nums">{value}</p></div><span className="rounded-lg bg-white/80 p-2 shadow-sm">{icon}</span></div></button>
}

function TypeCard({ active, label, code, value, onClick }: { active: boolean; label: string; code: string; value: number; onClick: () => void }) {
  return <button onClick={onClick} className={`rounded-xl border border-orange-200 bg-orange-50 px-5 py-4 text-left text-orange-600 transition-all hover:-translate-y-0.5 hover:shadow-md ${active ? 'ring-2 ring-orange-500 ring-offset-2' : ''}`}><div className="flex items-start justify-between gap-4"><div className="min-w-0"><p className="truncate text-sm font-bold text-slate-700">{label}</p><p className="mt-1 text-xs font-semibold text-orange-500">{code}</p></div><p className="text-3xl font-black tabular-nums">{value}</p></div></button>
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
          <DetailSection icon={<Activity className="h-4 w-4" />} title="隧道与结果"><div className="grid grid-cols-1 gap-3 md:grid-cols-2"><DetailValue label="请求 TEID" value={transaction.request_teid || '-'} /><DetailValue label="响应 TEID" value={transaction.response_teid || '-'} /><DetailValue label="Cause" value={`${transaction.cause || '-'} ${transaction.cause_name || ''}`} /><DetailValue label="APN" value={transaction.apn || '-'} /><DetailValue label="F-TEID IPv4" value={transaction.f_teid_ipv4 || '-'} /></div></DetailSection>
          <FilterCopy filter={transaction.wireshark_filter} copied={copied} onCopy={onCopy} />
        </div>
      </div>
    </div>
  )
}

function MessageDetailModal({ message, copied, onCopy, onClose }: { message: S11Message; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <ModalHeader title="S11 消息详情" subtitle={`Frame ${message.frame_number} · ${message.message_type}`} onClose={onClose} />
        <div className="space-y-5 p-6">
          <DetailSection icon={<Activity className="h-4 w-4" />} title="消息字段"><div className="grid grid-cols-1 gap-3 md:grid-cols-2"><DetailValue label="Message Type" value={`${message.message_type_code} · ${message.message_type}`} /><DetailValue label="Sequence" value={message.sequence_number} /><DetailValue label="TEID" value={message.teid || '-'} /><DetailValue label="Cause" value={`${message.cause || '-'} ${message.cause_name || ''}`} /><DetailValue label="APN" value={message.apn || '-'} /><DetailValue label="F-TEID IPv4" value={message.f_teid_ipv4 || '-'} /></div></DetailSection>
          <FilterCopy filter={message.wireshark_filter} copied={copied} onCopy={onCopy} />
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
  return <DetailSection icon={<Copy className="h-4 w-4" />} title="Wireshark 过滤器"><button onClick={onCopy} className="flex w-full items-center justify-between gap-3 rounded-lg bg-slate-100 px-4 py-3 text-left font-mono text-xs text-slate-700 hover:bg-slate-200"><span className="break-all">{filter}</span><span className="shrink-0 rounded-md bg-white px-2 py-1 font-sans text-xs font-bold text-orange-600">{copied ? '已复制' : '复制'}</span></button></DetailSection>
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
