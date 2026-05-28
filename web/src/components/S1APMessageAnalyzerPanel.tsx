import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { CheckCircle2, ChevronDown, Clock3, Copy, Layers3, Loader2, Network, Pause, Play, RefreshCw, Search, Upload, X, XCircle } from 'lucide-react'
import { copyText } from '../utils/clipboard'
import { readEventStream } from '../utils/eventStream'
import { PaginationControls } from './PaginationControls'
import { StreamProgressBar } from './StreamProgressBar'
import type { StreamProgress } from './StreamProgressBar'

interface S1APMessageAnalyzerPanelProps {
  jobId: string
}

type Direction = 'enb_to_mme' | 'mme_to_enb' | 'unknown'
type PDUType = 'initiating' | 'successful_outcome' | 'unsuccessful_outcome' | 'unknown'
type TransactionStatus = 'success' | 'failed' | 'in_progress'

interface S1APStatistics {
  total_messages: number
  initiating: number
  successful_outcome: number
  unsuccessful_outcome: number
  enb_to_mme: number
  mme_to_enb: number
  unknown_direction: number
  nas_transport: number
  erab: number
  ue_context: number
  transaction_capable_messages: number
  message_only_messages: number
  total_transactions: number
  successful_transactions: number
  failed_transactions: number
  in_progress_transactions: number
  transaction_success_rate: number
}

interface ProcedureCount {
  code: string
  name: string
  count: number
  filter: string
  transaction_capable: boolean
}

interface S1APMessage {
  id: string
  frame_number: number
  timestamp: string
  source_ip: string
  destination_ip: string
  direction: Direction
  procedure_code: string
  procedure_name: string
  pdu_code: string
  pdu_type: PDUType
  mme_ue_s1ap_id?: string
  enb_ue_s1ap_id?: string
  has_nas: boolean
  gtp_teid?: string
  erab_id?: string
  transaction_capable: boolean
  wireshark_filter: string
}

interface TransactionStep {
  frame_number: number
  timestamp: string
  direction: Direction
  procedure_name: string
  pdu_type: PDUType
}

interface S1APTransaction {
  id: string
  procedure_code: string
  procedure_name: string
  status: TransactionStatus
  start_frame: number
  end_frame?: number
  start_time: string
  end_time?: string
  duration_ms: number
  request_message: string
  result_message?: string
  mme_ue_s1ap_id?: string
  enb_ue_s1ap_id?: string
  erab_id?: string
  step_count: number
  steps: TransactionStep[]
  wireshark_filter: string
}

interface S1APAnalysisResult {
  filename: string
  analyzed_at: string
  total_packets: number
  truncated?: boolean
  message_limit?: number
  statistics: S1APStatistics
  messages: S1APMessage[]
  procedure_stats: ProcedureCount[]
  transactions: S1APTransaction[]
}

interface StreamPayload<T> {
  progress?: StreamProgress
  result?: T
  cached?: boolean
}

const directionLabels: Record<Direction, string> = {
  enb_to_mme: 'eNB -> MME',
  mme_to_enb: 'MME -> eNB',
  unknown: '未知',
}

const directionClasses: Record<Direction, string> = {
  enb_to_mme: 'bg-cyan-50 text-cyan-700 border-cyan-200',
  mme_to_enb: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  unknown: 'bg-slate-100 text-slate-600 border-slate-200',
}

const pduLabels: Record<PDUType, string> = {
  initiating: '发起',
  successful_outcome: '成功结果',
  unsuccessful_outcome: '失败结果',
  unknown: '未知',
}

const pduClasses: Record<PDUType, string> = {
  initiating: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  successful_outcome: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  unsuccessful_outcome: 'bg-rose-50 text-rose-700 border-rose-200',
  unknown: 'bg-slate-100 text-slate-600 border-slate-200',
}

const statusLabels: Record<TransactionStatus, string> = {
  success: '成功',
  failed: '失败',
  in_progress: '未完成',
}

const statusClasses: Record<TransactionStatus, string> = {
  success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  failed: 'bg-rose-50 text-rose-700 border-rose-200',
  in_progress: 'bg-amber-50 text-amber-700 border-amber-200',
}

type ProcedureFeatureTone = 'cyan' | 'emerald' | 'indigo' | 'amber' | 'rose' | 'slate' | 'violet' | 'sky' | 'orange'

interface ProcedureFeature {
  label: string
  tone: ProcedureFeatureTone
}

const procedureFeatureClasses: Record<ProcedureFeatureTone, string> = {
  cyan: 'border-cyan-200 bg-cyan-50 text-cyan-700',
  emerald: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  indigo: 'border-indigo-200 bg-indigo-50 text-indigo-700',
  amber: 'border-amber-200 bg-amber-50 text-amber-700',
  rose: 'border-rose-200 bg-rose-50 text-rose-700',
  slate: 'border-slate-200 bg-white text-slate-600',
  violet: 'border-violet-200 bg-violet-50 text-violet-700',
  sky: 'border-sky-200 bg-sky-50 text-sky-700',
  orange: 'border-orange-200 bg-orange-50 text-orange-700',
}

const s1apProcedureFeatures: Record<string, ProcedureFeature> = {
  '0': { label: '切换准备', tone: 'violet' },
  '1': { label: '切换资源', tone: 'violet' },
  '2': { label: '切换通知', tone: 'violet' },
  '3': { label: '路径切换', tone: 'violet' },
  '4': { label: '切换取消', tone: 'violet' },
  '5': { label: 'E-RAB', tone: 'orange' },
  '6': { label: 'E-RAB', tone: 'orange' },
  '7': { label: 'E-RAB', tone: 'orange' },
  '8': { label: 'E-RAB', tone: 'orange' },
  '9': { label: 'UE上下文', tone: 'emerald' },
  '10': { label: '寻呼', tone: 'sky' },
  '11': { label: 'NAS承载', tone: 'cyan' },
  '12': { label: '初始接入', tone: 'cyan' },
  '13': { label: 'NAS承载', tone: 'cyan' },
  '14': { label: '复位', tone: 'rose' },
  '15': { label: '异常', tone: 'rose' },
  '16': { label: 'NAS异常', tone: 'rose' },
  '17': { label: 'S1建链', tone: 'indigo' },
  '18': { label: 'UE上下文', tone: 'emerald' },
  '19': { label: 'CDMA2000', tone: 'slate' },
  '20': { label: 'CDMA2000', tone: 'slate' },
  '21': { label: 'UE上下文', tone: 'emerald' },
  '22': { label: 'UE能力', tone: 'emerald' },
  '23': { label: 'UE上下文', tone: 'emerald' },
  '24': { label: '状态转移', tone: 'slate' },
  '25': { label: '状态转移', tone: 'slate' },
  '26': { label: 'Trace', tone: 'slate' },
  '27': { label: 'Trace', tone: 'slate' },
  '28': { label: 'Trace异常', tone: 'rose' },
  '29': { label: 'eNB配置', tone: 'indigo' },
  '30': { label: 'MME配置', tone: 'indigo' },
  '31': { label: '位置上报', tone: 'sky' },
  '32': { label: '位置异常', tone: 'rose' },
  '33': { label: '位置报告', tone: 'sky' },
  '34': { label: '过载', tone: 'amber' },
  '35': { label: '过载', tone: 'amber' },
  '36': { label: '告警广播', tone: 'amber' },
  '37': { label: '直传', tone: 'slate' },
  '38': { label: '直传', tone: 'slate' },
  '39': { label: '私有消息', tone: 'slate' },
  '40': { label: '配置传递', tone: 'indigo' },
  '41': { label: '配置传递', tone: 'indigo' },
  '42': { label: '业务跟踪', tone: 'slate' },
  '43': { label: '告警广播', tone: 'amber' },
  '44': { label: 'LPPa定位', tone: 'sky' },
  '45': { label: 'LPPa定位', tone: 'sky' },
  '46': { label: 'LPPa定位', tone: 'sky' },
  '47': { label: 'LPPa定位', tone: 'sky' },
  '48': { label: 'UE能力', tone: 'emerald' },
  '49': { label: '告警状态', tone: 'amber' },
  '50': { label: 'E-RAB变更', tone: 'orange' },
  '51': { label: '告警异常', tone: 'rose' },
  '52': { label: 'NAS重路由', tone: 'cyan' },
  '53': { label: 'UE上下文', tone: 'emerald' },
  '54': { label: '连接建立', tone: 'cyan' },
  '55': { label: 'UE挂起', tone: 'emerald' },
  '56': { label: 'UE恢复', tone: 'emerald' },
  '57': { label: 'NAS递送', tone: 'cyan' },
  '58': { label: 'UE信息', tone: 'emerald' },
  '59': { label: 'UE信息', tone: 'emerald' },
  '60': { label: 'CP迁移', tone: 'violet' },
  '61': { label: 'CP迁移', tone: 'violet' },
  '62': { label: 'RAT用量', tone: 'orange' },
  '63': { label: 'UE能力', tone: 'emerald' },
  '64': { label: '切换成功', tone: 'violet' },
  '65': { label: '早期状态', tone: 'slate' },
  '66': { label: '早期状态', tone: 'slate' },
}

const PAGE_SIZE = 15

export function S1APMessageAnalyzerPanel({ jobId }: S1APMessageAnalyzerPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<S1APAnalysisResult | null>(null)
  const [progress, setProgress] = useState<StreamProgress | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [statusFilter, setStatusFilter] = useState<'all' | TransactionStatus>('all')
  const [procedureFilter, setProcedureFilter] = useState<string>('all')
  const [pduFilter, setPduFilter] = useState<'all' | PDUType>('all')
  const [query, setQuery] = useState('')
  const [listPage, setListPage] = useState(1)
  const [selectedTransaction, setSelectedTransaction] = useState<S1APTransaction | null>(null)
  const [selectedMessage, setSelectedMessage] = useState<S1APMessage | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [paused, setPaused] = useState(false)
  const abortControllerRef = useRef<AbortController | null>(null)
  const pausedRef = useRef(false)

  const fetchAnalysis = useCallback(async (nextProcedureFilter: string) => {
    abortControllerRef.current?.abort()
    const controller = new AbortController()
    abortControllerRef.current = controller
    pausedRef.current = false
    setPaused(false)
    setLoading(true)
    setError(null)
    setProgress(null)
    try {
      const requestBody: { limit: number; procedure_filter?: string; batch_rows: number } = { limit: 20000, batch_rows: 10000 }
      if (nextProcedureFilter !== 'all') requestBody.procedure_filter = nextProcedureFilter
      const response = await fetch(`/api/jobs/${jobId}/s1ap-messages/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify(requestBody),
      })
      await readEventStream<StreamPayload<S1APAnalysisResult> | string>(response, ({ event, data }) => {
        if (event === 'error') {
          throw new Error(typeof data === 'string' ? data : 'S1AP消息分析失败')
        }
        if (event === 'progress' && typeof data === 'object') {
          setProgress((data as StreamPayload<S1APAnalysisResult>).progress || {})
          return
        }
        if ((event === 'partial_result' || event === 'done') && typeof data === 'object') {
          const payload = data as StreamPayload<S1APAnalysisResult>
          if (payload.progress) setProgress(payload.progress)
          if (payload.result) setResult(payload.result)
        }
      }, { isPaused: () => pausedRef.current, signal: controller.signal })
      setSelectedTransaction(null)
      setSelectedMessage(null)
      return true
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        return false
      }
      setError('S1AP消息分析失败: ' + (err as Error).message)
      return false
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

  const handleAnalyze = useCallback(async () => {
    const ok = await fetchAnalysis('all')
    if (!ok) return
    setStatusFilter('all')
    setProcedureFilter('all')
    setPduFilter('all')
    setQuery('')
    setListPage(1)
  }, [fetchAnalysis])

  const handleProcedureSelect = useCallback(async (code: string) => {
    const nextProcedureFilter = procedureFilter === code ? 'all' : code
    setProcedureFilter(nextProcedureFilter)
    setStatusFilter('all')
    setListPage(1)
    await fetchAnalysis(nextProcedureFilter)
  }, [fetchAnalysis, procedureFilter])

  const handleClearFilters = useCallback(() => {
    const shouldReloadDefaultWindow = procedureFilter !== 'all'
    setStatusFilter('all')
    setProcedureFilter('all')
    setPduFilter('all')
    setQuery('')
    setListPage(1)
    if (shouldReloadDefaultWindow) {
      void fetchAnalysis('all')
    }
  }, [fetchAnalysis, procedureFilter])

  const filteredTransactions = useMemo(() => {
    if (!result) return []
    const normalizedQuery = query.trim().toLowerCase()
    return (result.transactions || []).filter(tx => {
      if (statusFilter !== 'all' && tx.status !== statusFilter) return false
      if (procedureFilter !== 'all' && tx.procedure_code !== procedureFilter) return false
      if (pduFilter !== 'all' && !tx.steps.some(step => step.pdu_type === pduFilter)) return false
      if (!normalizedQuery) return true
      return [
        tx.procedure_name,
        tx.procedure_code,
        tx.mme_ue_s1ap_id || '',
        tx.enb_ue_s1ap_id || '',
        tx.erab_id || '',
        String(tx.start_frame),
        tx.end_frame ? String(tx.end_frame) : '',
      ].some(value => value.toLowerCase().includes(normalizedQuery))
    }).sort((left, right) => {
      const rightDuration = right.duration_ms ?? -1
      const leftDuration = left.duration_ms ?? -1
      if (rightDuration !== leftDuration) return rightDuration - leftDuration
      return left.start_frame - right.start_frame
    })
  }, [result, statusFilter, procedureFilter, pduFilter, query])

  const filteredMessages = useMemo(() => {
    if (!result) return []
    const normalizedQuery = query.trim().toLowerCase()
    return (result.messages || []).filter(message => {
      if (procedureFilter !== 'all' && message.procedure_code !== procedureFilter) return false
      if (pduFilter !== 'all' && message.pdu_type !== pduFilter) return false
      if (!normalizedQuery) return true
      return [
        message.procedure_name,
        message.procedure_code,
        message.source_ip,
        message.destination_ip,
        message.mme_ue_s1ap_id || '',
        message.enb_ue_s1ap_id || '',
        message.erab_id || '',
        String(message.frame_number),
      ].some(value => value.toLowerCase().includes(normalizedQuery))
    })
  }, [result, procedureFilter, pduFilter, query])

  const unifiedRows = useMemo(() => {
    const transactionRows = filteredTransactions.map(tx => ({
      id: `tx:${tx.id}`,
      kind: 'transaction' as const,
      procedureName: tx.procedure_name,
      frameLabel: tx.end_frame ? `${tx.start_frame} -> ${tx.end_frame}` : String(tx.start_frame),
      sortDuration: tx.duration_ms ?? -1,
      sortFrame: tx.start_frame,
      tx,
      message: null,
    }))
    const messageRows = statusFilter === 'all' ? filteredMessages.map(message => ({
      id: `msg:${message.id}`,
      kind: 'message' as const,
      procedureName: message.procedure_name,
      frameLabel: String(message.frame_number),
      sortDuration: -1,
      sortFrame: message.frame_number,
      tx: null,
      message,
    })) : []
    return [...transactionRows, ...messageRows].sort((left, right) => {
      if (left.kind !== right.kind) return left.kind === 'transaction' ? -1 : 1
      if (left.sortDuration !== right.sortDuration) return right.sortDuration - left.sortDuration
      return left.sortFrame - right.sortFrame
    })
  }, [filteredTransactions, filteredMessages, statusFilter])

  const pagedRows = useMemo(() => paginate(unifiedRows, listPage), [unifiedRows, listPage])

  const handleCopy = useCallback(async (id: string, filter: string) => {
    const copied = await copyText(filter)
    if (!copied) return
    setCopiedId(id)
    window.setTimeout(() => setCopiedId(null), 1200)
  }, [])

  const stats = result?.statistics
  const procedureStats = (result?.procedure_stats || []).filter(item => item.count > 0)
  const transactionProcedures = procedureStats.filter(item => item.transaction_capable)
  const messageOnlyProcedures = procedureStats.filter(item => !item.transaction_capable)
  const transactionCountsByProcedure = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const tx of result?.transactions || []) {
      counts[tx.procedure_code] = (counts[tx.procedure_code] || 0) + 1
    }
    return counts
  }, [result])
  const transactionProcedureTotal = transactionProcedures.reduce((sum, item) => sum + (transactionCountsByProcedure[item.code] || 0), 0)
  const messageOnlyProcedureTotal = messageOnlyProcedures.reduce((sum, item) => sum + item.count, 0)
  const hasS1APMessages = (stats?.total_messages || 0) > 0
  const activeProcedureFeature = procedureFilter !== 'all' ? getS1APProcedureFeature(procedureFilter) : null
  const transactionMessageCounts = useMemo(() => {
    const counts: Record<TransactionStatus, number> = { success: 0, failed: 0, in_progress: 0 }
    for (const tx of result?.transactions || []) {
      counts[tx.status] += tx.step_count || tx.steps.length
    }
    return counts
  }, [result])

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 overflow-hidden">
      <div className={`${collapsed ? '' : 'border-b'} border-slate-200 bg-white px-5 py-4`}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-50 text-cyan-600 flex items-center justify-center border border-cyan-100">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-900">S1AP Message Analyzer</h3>
              <p className="text-xs text-slate-500">
                {collapsed && result ? `S1AP ${stats?.total_messages || 0} · 事务成功率 ${(stats?.transaction_success_rate || 0).toFixed(1)}%` : 'S1AP Procedure / PDU / UE Context 分析'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all active:scale-[0.98]"
            >
              {loading ? (paused ? <Pause className="w-4 h-4" /> : <Loader2 className="w-4 h-4 animate-spin" />) : result ? <RefreshCw className="w-4 h-4" /> : <Upload className="w-4 h-4" />}
              <span>{loading ? (paused ? '已暂停' : '分析中...') : result ? '重新分析' : '开始分析'}</span>
            </button>
            {loading && (
              <button
                onClick={handlePauseToggle}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-amber-50 px-3 py-2.5 text-sm font-semibold text-amber-700 transition-all hover:bg-amber-100 active:scale-[0.98]"
              >
                {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                <span>{paused ? '继续' : '暂停'}</span>
              </button>
            )}
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
          {loading && <StreamProgressBar progress={progress} label={paused ? '已暂停 S1AP 消息分析' : '正在流式分析 S1AP 消息'} />}
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
                    <TopMetric label="S1AP消息" value={stats?.total_messages || 0} />
                    <TopMetric label="事务消息" value={stats?.transaction_capable_messages || 0} accent="cyan" />
                    <TopMetric label="事务成功率" value={`${(stats?.transaction_success_rate || 0).toFixed(1)}%`} accent="emerald" />
                  </div>
                </div>
              </div>

              {result.truncated && (
                <div className="mb-6 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-800">
                  S1AP 消息数量过大，已分析前 {formatCount(result.message_limit || result.total_packets)} 条匹配消息并停止继续读取，避免环境卡死。
                </div>
              )}

              {!hasS1APMessages ? (
                <EmptyS1APState />
              ) : (
                <>
                  <div className="mb-6">
                    <p className="mb-3 text-sm font-bold text-slate-600">按 Procedure 统计（筛选消息列表）</p>
                    <div className="space-y-5">
                      <ProcedureGroup
                        title="事务流程"
                        summary={`共 ${transactionProcedureTotal} 个流程`}
                        items={transactionProcedures}
                        procedureFilter={procedureFilter}
                        columnsClass="xl:grid-cols-3"
                        getValue={item => transactionCountsByProcedure[item.code] || 0}
                        getValueDetail={item => `${item.count} 条消息`}
                        onSelect={handleProcedureSelect}
                      />
                      <ProcedureGroup
                        title="单向 / 承载消息"
                        summary={`共 ${messageOnlyProcedureTotal} 条消息`}
                        items={messageOnlyProcedures}
                        procedureFilter={procedureFilter}
                        columnsClass="xl:grid-cols-4"
                        getValue={item => item.count}
                        getValueDetail={() => '条消息'}
                        onSelect={handleProcedureSelect}
                      />
                    </div>
                  </div>

                  <div className="mb-6">
                    <p className="mb-3 text-sm font-bold text-slate-600">按 S1AP 事务状态统计</p>
                    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                      <FeatureCard active={statusFilter === 'success'} label="成功事务组" detail={`${transactionMessageCounts.success} 条消息`} value={stats?.successful_transactions || 0} tone="emerald" icon={<CheckCircle2 className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'success' ? 'all' : 'success'); setListPage(1) }} />
                      <FeatureCard active={statusFilter === 'failed'} label="失败事务组" detail={`${transactionMessageCounts.failed} 条消息`} value={stats?.failed_transactions || 0} tone="rose" icon={<XCircle className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'failed' ? 'all' : 'failed'); setListPage(1) }} />
                      <FeatureCard active={statusFilter === 'in_progress'} label="未完成事务组" detail={`${transactionMessageCounts.in_progress} 条消息`} value={stats?.in_progress_transactions || 0} tone="amber" icon={<Clock3 className="w-5 h-5" />} onClick={() => { setStatusFilter(statusFilter === 'in_progress' ? 'all' : 'in_progress'); setListPage(1) }} />
                    </div>
                  </div>

                  <div className="animate-fade-in rounded-xl border border-slate-200 overflow-hidden">
                    <div className="flex flex-col gap-3 border-b border-slate-200 bg-white px-4 py-4 md:flex-row md:items-center md:justify-between">
                      <div className="flex flex-wrap items-center gap-3">
                        <p className="text-base font-bold text-slate-900">S1AP Procedure 事务 / 消息列表</p>
                        <span className="text-sm text-slate-500">共 {unifiedRows.length} 条</span>
                        <FilterPill label={`事务：${filteredTransactions.length}`} />
                        <FilterPill label={`消息：${filteredMessages.length}`} />
                        {statusFilter !== 'all' && <FilterPill label={`状态：${statusLabels[statusFilter]}`} />}
                        {procedureFilter !== 'all' && <FilterPill label={`Procedure：${procedureFilter}${activeProcedureFeature ? ` · ${activeProcedureFeature.label}` : ''}`} />}
                        {pduFilter !== 'all' && <FilterPill label={`PDU：${pduLabels[pduFilter]}`} />}
                      </div>
                      <div className="flex flex-col gap-2 md:flex-row md:items-center">
                        {(statusFilter !== 'all' || procedureFilter !== 'all' || pduFilter !== 'all' || query.trim() !== '') && (
                          <button
                            onClick={handleClearFilters}
                            className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-500 hover:bg-slate-50 hover:text-slate-700"
                          >
                            清除消息筛选
                          </button>
                        )}
                        <select
                          value={pduFilter}
                          onChange={event => { setPduFilter(event.target.value as 'all' | PDUType); setListPage(1) }}
                          className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-semibold text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
                        >
                          <option value="all">全部 PDU</option>
                          <option value="initiating">发起</option>
                          <option value="successful_outcome">成功结果</option>
                          <option value="unsuccessful_outcome">失败结果</option>
                        </select>
                        <label className="relative block md:w-72">
                          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                          <input
                            value={query}
                            onChange={event => { setQuery(event.target.value); setListPage(1) }}
                            className="w-full rounded-lg border border-slate-200 bg-slate-50 pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-400"
                            placeholder="搜索 IP / UE ID / Procedure"
                          />
                        </label>
                      </div>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="min-w-full divide-y divide-slate-200 text-sm">
                        <thead className="bg-slate-50">
                          <tr>
                            <th className="px-4 py-3 text-left font-semibold text-cyan-700">类型</th>
                            <th className="px-4 py-3 text-left font-semibold text-cyan-700">Procedure</th>
                            <th className="px-4 py-3 text-left font-semibold text-cyan-700">状态 / PDU</th>
                            <th className="px-4 py-3 text-left font-semibold text-cyan-700">帧</th>
                            <th className="px-4 py-3 text-left font-semibold text-cyan-700">方向</th>
                            <th className="px-4 py-3 text-right font-semibold text-cyan-700">耗时</th>
                            <th className="px-4 py-3 text-left font-semibold text-cyan-700">eNB ID</th>
                            <th className="px-4 py-3 text-left font-semibold text-cyan-700">MME ID</th>
                            <th className="px-4 py-3 text-right font-semibold text-cyan-700">E-RAB / NAS</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 bg-white">
                          {pagedRows.map(row => (
                            <tr
                              key={row.id}
                              onClick={() => row.tx ? setSelectedTransaction(row.tx) : row.message && setSelectedMessage(row.message)}
                              className="cursor-pointer hover:bg-cyan-50/60"
                            >
                              <td className="px-4 py-3"><RowKindBadge kind={row.kind} /></td>
                              <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{row.procedureName}</td>
                              <td className="px-4 py-3">
                                {row.tx ? <StatusBadge status={row.tx.status} /> : row.message ? <PDUBadge pdu={row.message.pdu_type} /> : '-'}
                              </td>
                              <td className="px-4 py-3 font-mono text-slate-700 whitespace-nowrap">{row.frameLabel}</td>
                              <td className="px-4 py-3">{row.message ? <DirectionBadge direction={row.message.direction} /> : <span className="text-slate-300">-</span>}</td>
                              <td className="px-4 py-3 text-right font-semibold tabular-nums text-slate-900">{row.tx ? formatDuration(row.tx.duration_ms) : '-'}</td>
                              <td className="px-4 py-3 font-mono text-xs text-slate-600">{row.tx?.enb_ue_s1ap_id || row.message?.enb_ue_s1ap_id || '-'}</td>
                              <td className="px-4 py-3 font-mono text-xs text-slate-600">{row.tx?.mme_ue_s1ap_id || row.message?.mme_ue_s1ap_id || '-'}</td>
                              <td className="px-4 py-3 text-right font-semibold text-slate-700">
                                {row.tx ? row.tx.erab_id || row.tx.step_count : row.message?.erab_id || (row.message?.has_nas ? 'NAS' : '-')}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {unifiedRows.length === 0 && <div className="py-8 text-center text-sm text-slate-500">没有匹配的 S1AP 事务或消息</div>}
                    {unifiedRows.length > 0 && <PaginationControls total={unifiedRows.length} page={listPage} pageSize={PAGE_SIZE} onPageChange={setListPage} />}
                  </div>
                </>
              )}
            </>
          )}
        </div>
      )}

      {selectedTransaction && (
        <TransactionDetailModal
          transaction={selectedTransaction}
          copied={copiedId === selectedTransaction.id}
          onCopy={() => handleCopy(selectedTransaction.id, selectedTransaction.wireshark_filter)}
          onClose={() => setSelectedTransaction(null)}
        />
      )}
      {selectedMessage && (
        <MessageDetailModal
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

type Tone = 'emerald' | 'rose' | 'amber' | 'indigo' | 'cyan' | 'slate'

function FeatureCard({ active, label, detail, value, tone, icon, onClick }: { active: boolean; label: string; detail?: string; value: number; tone: Tone; icon: ReactNode; onClick: () => void }) {
  const toneClasses: Record<Tone, string> = {
    emerald: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    rose: 'text-rose-600 bg-rose-50 border-rose-200',
    amber: 'text-amber-600 bg-amber-50 border-amber-200',
    indigo: 'text-indigo-600 bg-indigo-50 border-indigo-200',
    cyan: 'text-cyan-600 bg-cyan-50 border-cyan-200',
    slate: 'text-slate-600 bg-slate-50 border-slate-200',
  }
  return (
    <button onClick={onClick} className={`min-h-24 rounded-xl border px-5 py-4 text-left transition-all hover:-translate-y-0.5 hover:shadow-md ${toneClasses[tone]} ${active ? 'ring-2 ring-cyan-500 ring-offset-2' : ''}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-bold opacity-80">{label}</p>
          <p className="mt-2 text-3xl font-black tabular-nums">{value}</p>
          {detail && <p className="mt-1 text-xs font-bold opacity-70">{detail}</p>}
        </div>
        <span className="rounded-lg bg-white/80 p-2 shadow-sm">{icon}</span>
      </div>
    </button>
  )
}

function ProcedureGroup({
  title,
  summary,
  items,
  procedureFilter,
  columnsClass,
  getValue,
  getValueDetail,
  onSelect,
}: {
  title: string
  summary: string
  items: ProcedureCount[]
  procedureFilter: string
  columnsClass: string
  getValue: (item: ProcedureCount) => number
  getValueDetail?: (item: ProcedureCount) => string
  onSelect: (code: string) => void
}) {
  if (items.length === 0) return null

  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <span className="h-2 w-2 rounded-full bg-cyan-500" />
        <p className="text-xs font-black text-slate-600">{title}</p>
        <span className="text-xs font-bold text-slate-400">{summary}</span>
      </div>
      <div className={`grid grid-cols-1 gap-4 md:grid-cols-2 ${columnsClass}`}>
        {items.map(item => (
          <ProcedureCard
            key={item.code}
            active={procedureFilter === item.code}
            label={item.name}
            code={`Procedure ${item.code}`}
            value={getValue(item)}
            valueDetail={getValueDetail?.(item)}
            feature={getS1APProcedureFeature(item.code)}
            transactionCapable={item.transaction_capable}
            onClick={() => onSelect(item.code)}
          />
        ))}
      </div>
    </div>
  )
}

function ProcedureCard({ active, label, code, value, valueDetail, feature, transactionCapable, onClick }: { active: boolean; label: string; code: string; value: number; valueDetail?: string; feature: ProcedureFeature; transactionCapable: boolean; onClick: () => void }) {
  return (
    <button title={code} onClick={onClick} className={`rounded-xl border border-cyan-200 bg-cyan-50 px-5 py-4 text-left text-cyan-600 transition-all hover:-translate-y-0.5 hover:shadow-md ${active ? 'ring-2 ring-cyan-500 ring-offset-2' : ''}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="truncate text-sm font-bold text-slate-700">{label}</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <ProcedureFeatureBadge feature={feature} />
            <span className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-bold ${transactionCapable ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-slate-200 bg-white text-slate-500'}`}>
              {transactionCapable ? '事务流程' : '单向消息'}
            </span>
          </div>
        </div>
        <div className="shrink-0 text-right">
          <p className="text-3xl font-black tabular-nums">{value}</p>
          {valueDetail && <p className="mt-1 text-xs font-black text-cyan-500">{valueDetail}</p>}
        </div>
      </div>
    </button>
  )
}

function ProcedureFeatureBadge({ feature }: { feature: ProcedureFeature }) {
  return <span className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-bold ${procedureFeatureClasses[feature.tone]}`}>{feature.label}</span>
}

function getS1APProcedureFeature(code: string): ProcedureFeature {
  return s1apProcedureFeatures[firstProcedureToken(code)] || { label: '其它过程', tone: 'slate' }
}

function firstProcedureToken(code: string): string {
  return String(code || '').trim().split(/[,\s;(]+/)[0] || ''
}

function DirectionBadge({ direction }: { direction: Direction }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${directionClasses[direction]}`}>{directionLabels[direction]}</span>
}

function PDUBadge({ pdu }: { pdu: PDUType }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${pduClasses[pdu]}`}>{pduLabels[pdu]}</span>
}

function StatusBadge({ status }: { status: TransactionStatus }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${statusClasses[status]}`}>{statusLabels[status]}</span>
}

function RowKindBadge({ kind }: { kind: 'transaction' | 'message' }) {
  const classes = kind === 'transaction' ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-slate-200 bg-slate-50 text-slate-600'
  return <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold ${classes}`}>{kind === 'transaction' ? '事务' : '消息'}</span>
}

function FilterPill({ label }: { label: string }) {
  return <span className="rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 text-xs font-bold text-cyan-700">{label}</span>
}

function EmptyS1APState() {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 px-5 py-8 text-center">
      <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500">
        <Network className="h-5 w-5" />
      </div>
      <p className="mt-4 text-base font-bold text-slate-900">未发现 S1AP 消息</p>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-500">
        当前抓包没有被 tshark 识别出的 S1AP 协议帧，可能是该文件只包含 NGAP、PFCP、GTPv2、Diameter、SIP 等其他协议。
      </p>
    </div>
  )
}

function TransactionDetailModal({ transaction, copied, onCopy, onClose }: { transaction: S1APTransaction; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <ModalHeader title="S1AP 事务详情" subtitle={`${transaction.procedure_name} · Frame ${transaction.start_frame}-${transaction.end_frame || transaction.start_frame}`} onClose={onClose} />
        <div className="space-y-5 p-6">
          <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-bold text-cyan-700">Procedure {transaction.procedure_code}</p>
                <p className="mt-1 text-2xl font-black text-slate-900">{transaction.procedure_name}</p>
              </div>
              <StatusBadge status={transaction.status} />
            </div>
          </div>
          <DetailSection icon={<Clock3 className="h-4 w-4" />} title="时间信息">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <DetailValue label="开始时间" value={formatTimestamp(transaction.start_time)} />
              <DetailValue label="结束时间" value={transaction.end_time ? formatTimestamp(transaction.end_time) : '-'} />
              <DetailValue label="耗时" value={formatDuration(transaction.duration_ms)} />
            </div>
          </DetailSection>
          <DetailSection icon={<Network className="h-4 w-4" />} title="UE 上下文">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <DetailValue label="eNB UE S1AP ID" value={transaction.enb_ue_s1ap_id || '-'} />
              <DetailValue label="MME UE S1AP ID" value={transaction.mme_ue_s1ap_id || '-'} />
              <DetailValue label="E-RAB ID" value={transaction.erab_id || '-'} />
            </div>
          </DetailSection>
          <DetailSection icon={<Layers3 className="h-4 w-4" />} title="事务步骤">
            <div className="space-y-2">
              {transaction.steps.map(step => (
                <div key={`${step.frame_number}:${step.pdu_type}`} className="grid grid-cols-[72px_96px_96px_1fr] items-center gap-3 rounded-lg bg-white px-3 py-2 text-sm">
                  <span className="font-mono font-bold text-slate-700">{step.frame_number}</span>
                  <span className="font-mono text-xs font-semibold text-slate-500">{formatTimestamp(step.timestamp)}</span>
                  <DirectionBadge direction={step.direction} />
                  <span className="font-semibold text-slate-800">{pduLabels[step.pdu_type]}</span>
                </div>
              ))}
            </div>
          </DetailSection>
          <FilterCopy filter={transaction.wireshark_filter} copied={copied} onCopy={onCopy} />
        </div>
      </div>
    </div>
  )
}

function MessageDetailModal({ message, copied, onCopy, onClose }: { message: S1APMessage; copied: boolean; onCopy: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white shadow-2xl">
        <ModalHeader title="S1AP 消息详情" subtitle={`Frame ${message.frame_number} · ${message.procedure_name}`} onClose={onClose} />
        <div className="space-y-5 p-6">
          <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-bold text-cyan-700">Procedure {message.procedure_code}</p>
                <p className="mt-1 text-2xl font-black text-slate-900">{message.procedure_name}</p>
              </div>
              <PDUBadge pdu={message.pdu_type} />
            </div>
          </div>
          <DetailSection icon={<Network className="h-4 w-4" />} title="网络与 UE 上下文">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <DetailValue label="源地址" value={message.source_ip} />
              <DetailValue label="目的地址" value={message.destination_ip} />
              <DetailValue label="eNB UE S1AP ID" value={message.enb_ue_s1ap_id || '-'} />
              <DetailValue label="MME UE S1AP ID" value={message.mme_ue_s1ap_id || '-'} />
              <DetailValue label="E-RAB ID" value={message.erab_id || '-'} />
              <DetailValue label="GTP TEID" value={message.gtp_teid || '-'} />
            </div>
          </DetailSection>
          <DetailSection icon={<Layers3 className="h-4 w-4" />} title="S1AP 信息">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <DetailValue label="方向" value={directionLabels[message.direction]} />
              <DetailValue label="PDU Code" value={message.pdu_code || '-'} />
              <DetailValue label="包含 NAS" value={message.has_nas ? '是' : '否'} />
            </div>
          </DetailSection>
          <FilterCopy filter={message.wireshark_filter} copied={copied} onCopy={onCopy} />
        </div>
      </div>
    </div>
  )
}

function ModalHeader({ title, subtitle, onClose }: { title: string; subtitle: string; onClose: () => void }) {
  return (
    <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-200 bg-white px-6 py-4">
      <div className="min-w-0">
        <h4 className="text-xl font-bold text-slate-900">{title}</h4>
        <p className="mt-1 truncate text-sm text-slate-500">{subtitle}</p>
      </div>
      <button onClick={onClose} className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700">
        <X className="h-5 w-5" />
      </button>
    </div>
  )
}

function DetailSection({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-bold text-slate-700">
        <span className="text-cyan-600">{icon}</span>
        <span>{title}</span>
      </div>
      {children}
    </section>
  )
}

function DetailValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-white px-3 py-2">
      <p className="text-xs font-semibold text-slate-400">{label}</p>
      <p className="mt-1 break-all font-mono text-sm font-bold text-slate-800">{value}</p>
    </div>
  )
}

function FilterCopy({ filter, copied, onCopy }: { filter: string; copied: boolean; onCopy: () => void }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="mb-2 flex items-center justify-between gap-3">
        <p className="text-sm font-bold text-slate-700">Wireshark Filter</p>
        <button onClick={onCopy} className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-xs font-bold text-white hover:bg-slate-800">
          <Copy className="h-3.5 w-3.5" />
          {copied ? '已复制' : '复制'}
        </button>
      </div>
      <pre className="max-h-36 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-white p-3 text-xs font-semibold text-slate-700">{filter}</pre>
    </div>
  )
}

function paginate<T>(items: T[], page: number): T[] {
  const start = (page - 1) * PAGE_SIZE
  return items.slice(start, start + PAGE_SIZE)
}

function formatDuration(value?: number): string {
  if (value == null || Number.isNaN(value)) return '-'
  if (value < 1000) return `${value.toFixed(1)} ms`
  return `${(value / 1000).toFixed(2)} s`
}

function formatTimestamp(value?: string): string {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleTimeString()
}

function shortFilename(filename: string): string {
  const normalized = filename.replace(/\\/g, '/')
  return normalized.split('/').filter(Boolean).pop() || filename
}

function formatCount(value: number): string {
  return new Intl.NumberFormat('zh-CN').format(value)
}
