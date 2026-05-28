import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode, Ref, UIEvent } from 'react'
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ClipboardPaste,
  FileArchive,
  FileDiff,
  Loader2,
  Maximize2,
  Minimize2,
  RefreshCw,
  Search,
  UploadCloud,
  X,
} from 'lucide-react'
import { PaginationControls } from './PaginationControls'

interface PacketCompareProps {
  onBack: () => void
}

interface APIResponse<T> {
  success: boolean
  data?: T
  error?: string
}

interface UploadedJob {
  id: string
  fileCount: number
  filename: string
}

type CaptureSide = 'left' | 'right'
type ProtocolKey = 'ngap' | 's1ap' | 'nas' | 'sm-nas' | 's11' | 'pfcp'

interface ComparableMessage {
  id: string
  protocol: ProtocolKey
  treeProtocol: string
  frameNumber: number
  timestamp?: string
  sourceIp?: string
  destinationIp?: string
  typeKey: string
  typeLabel: string
  typeCode?: string
  directionLabel?: string
  context?: string
  filter?: string
  tags?: string[]
}

interface CaptureState {
  job: UploadedJob | null
  messages: ComparableMessage[]
  loading: boolean
  error: string | null
  selectedId: string | null
  query: string
  typeFilter: string
  page: number
}

interface PacketTreeResponse {
  frame: number
  protocol: string
  tree: string
  cached: boolean
}

interface ProtocolConfig {
  key: ProtocolKey
  label: string
  detail: string
  endpoint: string
  requestBody: Record<string, unknown>
  normalize: (data: any) => ComparableMessage[]
}

type DiffKind = 'same' | 'changed' | 'left' | 'right'

interface DiffRow {
  kind: DiffKind
  left?: string
  right?: string
  leftLineNumber?: number
  rightLineNumber?: number
  alignedLineNumber?: number
  leftSegments?: DiffSegment[]
  rightSegments?: DiffSegment[]
}

interface DiffSegment {
  text: string
  highlighted: boolean
}

interface ParsedTreeLine {
  line: string
  key: string
  familyKey: string
  moveBlockKey: string
  anchorKey: string
  index: number
  indent: number
  blockEnd: number
  containingBlockEnd: number
}

interface PositionHint {
  id: string
  label: string
  leftLine: string
  rightLine: string
  leftLineNumber: number
  rightLineNumber: number
  alignedLineNumber: number
}

interface StructureDiffResult {
  rows: DiffRow[]
  positionHints: PositionHint[]
}

interface ComparisonResult {
  title: string
  subtitle: string
  leftTree: string
  rightTree: string
  rows: DiffRow[]
  positionHints: PositionHint[]
}

const PAGE_SIZE = 12
const pcapFilenamePattern = /\.(pcap\d*|pcapng|cap)$/i

const emptyCaptureState: CaptureState = {
  job: null,
  messages: [],
  loading: false,
  error: null,
  selectedId: null,
  query: '',
  typeFilter: 'all',
  page: 1,
}

const protocolConfigs: ProtocolConfig[] = [
  {
    key: 'ngap',
    label: 'NGAP',
    detail: '5GC N2 signaling',
    endpoint: 'ngap-messages',
    requestBody: { limit: 20000 },
    normalize: normalizeNGAPMessages,
  },
  {
    key: 's1ap',
    label: 'S1AP',
    detail: 'EPC S1 signaling',
    endpoint: 's1ap-messages',
    requestBody: { limit: 20000 },
    normalize: normalizeS1APMessages,
  },
  {
    key: 'nas',
    label: '5G NAS',
    detail: '5GMM / 5GSM messages',
    endpoint: 'nas-messages',
    requestBody: { limit: 20000 },
    normalize: normalizeNASMessages,
  },
  {
    key: 'sm-nas',
    label: 'SM NAS',
    detail: 'PDU session NAS-SM',
    endpoint: 'sm-nas-messages',
    requestBody: { limit: 20000 },
    normalize: normalizeSMNASMessages,
  },
  {
    key: 's11',
    label: 'S11',
    detail: 'GTPv2-C request / response',
    endpoint: 's11-messages',
    requestBody: { limit: 20000 },
    normalize: normalizeS11Messages,
  },
  {
    key: 'pfcp',
    label: 'PFCP',
    detail: 'PFCP request / response',
    endpoint: 'pfcp-sessions',
    requestBody: { limit: 20000, timeout_seconds: 3 },
    normalize: normalizePFCPMessages,
  },
]

const defaultProtocolSelection = protocolConfigs.map(item => item.key)

export function PacketCompare({ onBack }: PacketCompareProps) {
  const [protocols, setProtocols] = useState<ProtocolKey[]>(defaultProtocolSelection)
  const [captures, setCaptures] = useState<Record<CaptureSide, CaptureState>>({
    left: { ...emptyCaptureState },
    right: { ...emptyCaptureState },
  })
  const [comparison, setComparison] = useState<ComparisonResult | null>(null)
  const [compareError, setCompareError] = useState<string | null>(null)
  const [comparing, setComparing] = useState(false)
  const [pasteInputOpen, setPasteInputOpen] = useState(false)
  const [pasteDrafts, setPasteDrafts] = useState<Record<CaptureSide, string>>({ left: '', right: '' })
  const [pasteCompareError, setPasteCompareError] = useState<string | null>(null)

  const selectedConfigs = useMemo(() => protocolConfigs.filter(item => protocols.includes(item.key)), [protocols])
  const protocolLabel = useMemo(() => formatProtocolSelectionLabel(selectedConfigs), [selectedConfigs])
  const leftSelected = useMemo(() => selectedMessage(captures.left), [captures.left])
  const rightSelected = useMemo(() => selectedMessage(captures.right), [captures.right])
  const selectedTypeMismatch = !!leftSelected && !!rightSelected && leftSelected.typeKey !== rightSelected.typeKey
  const canCompare = !!leftSelected && !!rightSelected && !selectedTypeMismatch

  const updateCapture = useCallback((side: CaptureSide, updater: (previous: CaptureState) => CaptureState) => {
    setCaptures(previous => ({
      ...previous,
      [side]: updater(previous[side]),
    }))
  }, [])

  const handleProtocolToggle = useCallback((nextProtocol: ProtocolKey) => {
    const nextProtocols = protocols.includes(nextProtocol)
      ? protocols.filter(item => item !== nextProtocol)
      : protocolConfigs
        .map(item => item.key)
        .filter(item => item === nextProtocol || protocols.includes(item))
    if (nextProtocols.length === 0) return

    setProtocols(nextProtocols)
    setComparison(null)
    setCompareError(null)
    setPasteInputOpen(false)
    setPasteCompareError(null)
    setCaptures(previous => ({
      left: resetCaptureAnalysis(previous.left),
      right: resetCaptureAnalysis(previous.right),
    }))
  }, [protocols])

  const handleUploaded = useCallback((side: CaptureSide, job: UploadedJob) => {
    updateCapture(side, previous => ({
      ...resetCaptureAnalysis(previous),
      job,
    }))
    setComparison(null)
    setCompareError(null)
    setPasteInputOpen(false)
    setPasteCompareError(null)
  }, [updateCapture])

  const handleClearJob = useCallback((side: CaptureSide) => {
    updateCapture(side, () => ({ ...emptyCaptureState }))
    setComparison(null)
    setCompareError(null)
    setPasteInputOpen(false)
    setPasteCompareError(null)
  }, [updateCapture])

  const loadMessages = useCallback(async (side: CaptureSide) => {
    const capture = captures[side]
    if (!capture.job) return

    updateCapture(side, previous => ({
      ...previous,
      loading: true,
      error: null,
      messages: [],
      selectedId: null,
      page: 1,
      typeFilter: 'all',
    }))
    setComparison(null)
    setCompareError(null)
    setPasteInputOpen(false)
    setPasteCompareError(null)

    try {
      const results = await Promise.allSettled(selectedConfigs.map(item => fetchMessagesForProtocol(capture.job!.id, item)))
      const messages = results
        .flatMap(result => result.status === 'fulfilled' ? result.value.messages : [])
        .sort((left, right) => left.frameNumber - right.frameNumber || left.protocol.localeCompare(right.protocol))
      const failures = results.flatMap(result => result.status === 'rejected' ? [(result.reason as Error).message] : [])
      if (messages.length === 0 && failures.length > 0) {
        throw new Error(failures.join('；'))
      }
      updateCapture(side, previous => ({
        ...previous,
        loading: false,
        messages,
        error: failures.length > 0 ? `部分协议分析失败: ${failures.join('；')}` : null,
      }))
    } catch (err) {
      updateCapture(side, previous => ({
        ...previous,
        loading: false,
        error: `${protocolLabel} 消息分析失败: ${(err as Error).message}`,
      }))
    }
  }, [captures, protocolLabel, selectedConfigs, updateCapture])

  const loadBothMessages = useCallback(async () => {
    await Promise.all([
      captures.left.job ? loadMessages('left') : Promise.resolve(),
      captures.right.job ? loadMessages('right') : Promise.resolve(),
    ])
  }, [captures.left.job, captures.right.job, loadMessages])

  const handleSelectMessage = useCallback((side: CaptureSide, message: ComparableMessage) => {
    updateCapture(side, previous => ({
      ...previous,
      selectedId: previous.selectedId === message.id ? null : message.id,
    }))
    setComparison(null)
    setCompareError(null)
    setPasteInputOpen(false)
    setPasteCompareError(null)
  }, [updateCapture])

  const handleCompare = useCallback(async () => {
    const left = selectedMessage(captures.left)
    const right = selectedMessage(captures.right)
    if (!left || !right) {
      setCompareError('请先在左右两侧各选择一条消息')
      return
    }
    if (left.typeKey !== right.typeKey) {
      setCompareError('左右消息类型不一致，请选择相同类型后再对比')
      return
    }
    if (!captures.left.job || !captures.right.job) return

    setComparing(true)
    setCompareError(null)
    try {
      const [leftTree, rightTree] = await Promise.all([
        fetchPacketTree(captures.left.job.id, left),
        fetchPacketTree(captures.right.job.id, right),
      ])
      const diffResult = buildLineDiff(leftTree, rightTree)
      setComparison({
        title: left.typeLabel,
        subtitle: `左 Frame ${left.frameNumber} · 右 Frame ${right.frameNumber} · ${left.treeProtocol}`,
        leftTree,
        rightTree,
        rows: diffResult.rows,
        positionHints: diffResult.positionHints,
      })
      setPasteInputOpen(false)
      setPasteCompareError(null)
    } catch (err) {
      setCompareError('消息详情对比失败: ' + (err as Error).message)
    } finally {
      setComparing(false)
    }
  }, [captures.left, captures.right])

  const handlePasteDraftChange = useCallback((side: CaptureSide, value: string) => {
    setPasteDrafts(previous => ({ ...previous, [side]: value }))
    setPasteCompareError(null)
  }, [])

  const handleOpenPasteInput = useCallback(() => {
    setPasteInputOpen(true)
    setPasteCompareError(null)
    if (!comparison) {
      setComparison(createEmptyPasteComparison())
    }
  }, [comparison])

  const handleClosePasteInput = useCallback(() => {
    setPasteInputOpen(false)
    setPasteCompareError(null)
  }, [])

  const handleComparePastedContent = useCallback(() => {
    try {
      const leftTree = pastedInputToTree(pasteDrafts.left, '左侧内容')
      const rightTree = pastedInputToTree(pasteDrafts.right, '右侧内容')
      const diffResult = buildLineDiff(leftTree, rightTree)
      setComparison({
        title: '复制内容结构对比',
        subtitle: '左侧复制内容 · 右侧复制内容 · 已忽略具体值差异',
        leftTree,
        rightTree,
        rows: diffResult.rows,
        positionHints: diffResult.positionHints,
      })
      setPasteInputOpen(false)
      setPasteCompareError(null)
      setCompareError(null)
    } catch (err) {
      setPasteCompareError((err as Error).message)
    }
  }, [pasteDrafts.left, pasteDrafts.right])

  const diffStats = useMemo(() => getDiffStats(comparison?.rows || []), [comparison])
  const structureDiffCount = diffStats.changed + diffStats.left + diffStats.right

  return (
    <div className="min-h-screen bg-[#eef3f8] text-slate-900">
      <header className="sticky top-0 z-40 border-b border-slate-200 bg-white shadow-sm backdrop-blur-md">
        <div className="mx-auto flex h-[72px] max-w-[1720px] items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onBack}
              className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-600 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900"
              aria-label="返回"
            >
              <ArrowLeft className="h-5 w-5" />
            </button>
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-teal-200 bg-teal-50 text-teal-700 shadow-sm">
              <FileDiff className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-black text-slate-950">双抓包消息对比</h1>
              <p className="text-xs font-bold text-slate-500">左右导入抓包，选择相同类型消息后查看字段差异</p>
            </div>
          </div>
          <button
            type="button"
            onClick={loadBothMessages}
            disabled={!captures.left.job || !captures.right.job || captures.left.loading || captures.right.loading}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-950 px-4 py-2.5 text-sm font-black text-white shadow-sm shadow-slate-950/15 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:shadow-none"
          >
            {captures.left.loading || captures.right.loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            <span>分析左右消息</span>
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-[1720px] px-4 py-8 sm:px-6 lg:px-8">
        <section className="mb-6 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm shadow-slate-200/70">
          <div className="h-1 bg-slate-950" />
          <div className="p-4">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="min-w-[260px]">
              <p className="text-sm font-black text-slate-950">选择消息协议</p>
              <p className="mt-1 text-sm font-semibold text-slate-500">可多选，调整协议会清空当前消息列表和对比结果</p>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
              {protocolConfigs.map(item => {
                const selected = protocols.includes(item.key)
                return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => handleProtocolToggle(item.key)}
                  className={`group relative min-h-[58px] rounded-lg border px-3 py-2 text-left transition ${
                    selected
                      ? 'border-teal-600 bg-teal-600 text-white shadow-sm shadow-teal-600/20'
                      : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  <span className="flex items-center justify-between gap-2 text-sm font-black">
                    {item.label}
                    {selected && <CheckCircle2 className="h-4 w-4 shrink-0 text-white" />}
                  </span>
                  <span className="mt-0.5 block truncate text-xs font-bold opacity-75">{item.detail}</span>
                </button>
              )})}
            </div>
          </div>
          </div>
        </section>

        <section className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
          <CaptureColumn
            side="left"
            title="左侧抓包"
            protocolLabel={protocolLabel}
            capture={captures.left}
            counterpartTypeKey={rightSelected?.typeKey || null}
            onUploaded={job => handleUploaded('left', job)}
            onClearJob={() => handleClearJob('left')}
            onAnalyze={() => loadMessages('left')}
            onSelect={message => handleSelectMessage('left', message)}
            onQueryChange={query => updateCapture('left', previous => ({ ...previous, query, page: 1 }))}
            onTypeFilterChange={typeFilter => updateCapture('left', previous => ({ ...previous, typeFilter, page: 1 }))}
            onPageChange={page => updateCapture('left', previous => ({ ...previous, page }))}
          />
          <CaptureColumn
            side="right"
            title="右侧抓包"
            protocolLabel={protocolLabel}
            capture={captures.right}
            counterpartTypeKey={leftSelected?.typeKey || null}
            onUploaded={job => handleUploaded('right', job)}
            onClearJob={() => handleClearJob('right')}
            onAnalyze={() => loadMessages('right')}
            onSelect={message => handleSelectMessage('right', message)}
            onQueryChange={query => updateCapture('right', previous => ({ ...previous, query, page: 1 }))}
            onTypeFilterChange={typeFilter => updateCapture('right', previous => ({ ...previous, typeFilter, page: 1 }))}
            onPageChange={page => updateCapture('right', previous => ({ ...previous, page }))}
          />
        </section>

        <section className="mb-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm shadow-slate-200/70">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <SelectionSummary left={leftSelected} right={rightSelected} mismatch={selectedTypeMismatch} />
            <div className="flex flex-wrap items-center gap-3">
              {compareError && (
                <span className="inline-flex items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-bold text-rose-700">
                  <AlertCircle className="h-4 w-4" />
                  {compareError}
                </span>
              )}
              <button
                type="button"
                onClick={handleCompare}
                disabled={!canCompare || comparing}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-teal-600 px-5 py-2.5 text-sm font-black text-white shadow-sm shadow-teal-600/20 transition hover:bg-teal-700 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:shadow-none"
              >
                {comparing ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileDiff className="h-4 w-4" />}
                <span>{comparing ? '正在对比...' : '对比所选消息'}</span>
              </button>
              <button
                type="button"
                onClick={handleOpenPasteInput}
                className="inline-flex items-center justify-center gap-2 rounded-lg border border-sky-200 bg-sky-50 px-4 py-2.5 text-sm font-black text-sky-700 transition hover:border-sky-300 hover:bg-white"
              >
                <ClipboardPaste className="h-4 w-4" />
                <span>粘贴内容对比</span>
              </button>
            </div>
          </div>
        </section>

        {comparison && (
          <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm shadow-slate-200/70">
            <div className="border-b border-slate-200 bg-white px-5 py-4">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <p className="text-base font-black text-slate-900">{comparison.title}</p>
                  <p className="mt-1 text-sm font-semibold text-slate-500">{comparison.subtitle}</p>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs font-black">
                  {pasteCompareError && (
                    <span className="inline-flex rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-rose-700">
                      {pasteCompareError}
                    </span>
                  )}
                  <SummaryPill label="结构差异" value={structureDiffCount} title="结构无法完全对齐的数量，已忽略具体值差异" className="border-amber-200 bg-amber-50 text-amber-700" />
                  <SummaryPill label="位置调整" value={comparison.positionHints.length} title="同一结构在左右消息中出现位置不同，需要按中间两列对齐查看" className="border-blue-200 bg-blue-50 text-blue-700" />
                  <SummaryPill label="结构相同" value={diffStats.same} title="结构相同，具体值可能不同但已忽略" className="border-slate-200 bg-white text-slate-600" />
                </div>
              </div>
            </div>
            <FourPaneDiffViewer
              leftTree={comparison.leftTree}
              rightTree={comparison.rightTree}
              rows={comparison.rows}
              hints={comparison.positionHints}
              pasteInputOpen={pasteInputOpen}
              pasteDrafts={pasteDrafts}
              pasteCompareError={pasteCompareError}
              onPasteDraftChange={handlePasteDraftChange}
              onOpenPasteInput={handleOpenPasteInput}
              onClosePasteInput={handleClosePasteInput}
              onComparePastedContent={handleComparePastedContent}
            />
          </section>
        )}
      </main>
    </div>
  )
}

function CaptureColumn({
  side,
  title,
  protocolLabel,
  capture,
  counterpartTypeKey,
  onUploaded,
  onClearJob,
  onAnalyze,
  onSelect,
  onQueryChange,
  onTypeFilterChange,
  onPageChange,
}: {
  side: CaptureSide
  title: string
  protocolLabel: string
  capture: CaptureState
  counterpartTypeKey: string | null
  onUploaded: (job: UploadedJob) => void
  onClearJob: () => void
  onAnalyze: () => void
  onSelect: (message: ComparableMessage) => void
  onQueryChange: (query: string) => void
  onTypeFilterChange: (typeFilter: string) => void
  onPageChange: (page: number) => void
}) {
  const typeOptions = useMemo(() => buildTypeOptions(capture.messages), [capture.messages])
  const filteredMessages = useMemo(() => filterMessages(capture), [capture])
  const pagedMessages = useMemo(() => paginate(filteredMessages, capture.page), [filteredMessages, capture.page])

  return (
    <div className={`overflow-hidden rounded-xl border bg-white shadow-sm shadow-slate-200/70 ${side === 'left' ? 'border-teal-200' : 'border-sky-200'}`}>
      <div className={`h-1 ${side === 'left' ? 'bg-teal-500' : 'bg-sky-500'}`} />
      <div className={`border-b px-5 py-4 ${side === 'left' ? 'border-teal-100 bg-teal-50/80' : 'border-sky-100 bg-sky-50/80'}`}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-base font-black text-slate-950">{title}</p>
            <p className="mt-1 text-sm font-bold text-slate-500">{protocolLabel} 消息列表</p>
          </div>
          {capture.job && (
            <button
              type="button"
              onClick={onClearJob}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-black text-slate-500 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 hover:text-slate-800"
            >
              重新导入
            </button>
          )}
        </div>
      </div>

      <div className="p-5">
        <UploadSlot side={side} job={capture.job} onUploaded={onUploaded} />

        {capture.job && (
          <div className="mt-4 flex flex-col gap-3 border-t border-slate-100 pt-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <button
                type="button"
                onClick={onAnalyze}
                disabled={capture.loading}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-950 px-4 py-2.5 text-sm font-black text-white shadow-sm shadow-slate-950/15 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:shadow-none"
              >
                {capture.loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                <span>{capture.messages.length > 0 ? '重新分析消息' : '分析消息'}</span>
              </button>
              <span className="text-sm font-bold text-slate-500">
                {capture.loading ? '分析中...' : `已载入 ${capture.messages.length} 条`}
              </span>
            </div>

            {capture.error && (
              <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-bold text-rose-700">
                {capture.error}
              </div>
            )}

            {capture.messages.length > 0 && (
              <>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-[minmax(0,1fr)_180px]">
                  <label className="relative block">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                    <input
                      value={capture.query}
                      onChange={event => onQueryChange(event.target.value)}
                      className="w-full rounded-lg border border-slate-200 bg-white py-2 pl-9 pr-3 text-sm font-semibold text-slate-700 outline-none transition focus:border-teal-400 focus:ring-2 focus:ring-teal-100"
                      placeholder="搜索帧号 / IP / 类型"
                    />
                  </label>
                  <select
                    value={capture.typeFilter}
                    onChange={event => onTypeFilterChange(event.target.value)}
                    className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-bold text-slate-600 outline-none transition focus:border-teal-400 focus:ring-2 focus:ring-teal-100"
                  >
                    <option value="all">全部类型</option>
                    {typeOptions.map(option => (
                      <option key={option.key} value={option.key}>{option.label} ({option.count})</option>
                    ))}
                  </select>
                </div>

                <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
                  <div className="max-h-[520px] overflow-y-auto bg-white">
                    {pagedMessages.map(message => {
                      const selected = capture.selectedId === message.id
                      const compatible = !counterpartTypeKey || counterpartTypeKey === message.typeKey
                      return (
                        <button
                          key={message.id}
                          type="button"
                          onClick={() => onSelect(message)}
                          className={`flex w-full items-start gap-3 border-b border-l-4 px-4 py-3 text-left last:border-b-0 transition ${
                            selected
                              ? 'border-b-teal-100 border-l-teal-500 bg-teal-50 ring-1 ring-inset ring-teal-300'
                              : compatible
                                ? 'border-b-slate-100 border-l-transparent hover:bg-slate-50/80'
                                : 'border-b-slate-100 border-l-transparent bg-slate-50/60 opacity-60 hover:opacity-100'
                          }`}
                        >
                          <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md border ${selected ? 'border-teal-500 bg-teal-500 text-white' : 'border-slate-300 bg-white text-transparent'}`}>
                            <CheckCircle2 className="h-4 w-4" />
                          </span>
                          <span className="min-w-0 flex-1">
                            <span className="flex flex-wrap items-center gap-2">
                              <Badge className="border-blue-200 bg-blue-50 text-blue-700">{displayProtocolLabel(message.protocol)}</Badge>
                              <span className="font-black text-slate-950">{message.typeLabel}</span>
                              {message.typeCode && <Badge>{message.typeCode}</Badge>}
                              {message.directionLabel && <Badge>{message.directionLabel}</Badge>}
                              {!compatible && <Badge className="border-amber-200 bg-amber-50 text-amber-700">类型不同</Badge>}
                            </span>
                            <span className="mt-1 block text-xs font-bold text-slate-500">
                              Frame {message.frameNumber}
                              {message.timestamp ? ` · ${formatTimestamp(message.timestamp)}` : ''}
                              {message.sourceIp || message.destinationIp ? ` · ${message.sourceIp || '-'} -> ${message.destinationIp || '-'}` : ''}
                            </span>
                            {message.context && <span className="mt-1 block truncate text-xs font-semibold text-slate-500">{message.context}</span>}
                          </span>
                        </button>
                      )
                    })}
                  </div>
                  {filteredMessages.length === 0 ? (
                    <div className="bg-white px-4 py-8 text-center text-sm font-semibold text-slate-500">没有匹配的消息</div>
                  ) : (
                    <PaginationControls total={filteredMessages.length} page={capture.page} pageSize={PAGE_SIZE} onPageChange={onPageChange} />
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function UploadSlot({ side, job, onUploaded }: { side: CaptureSide; job: UploadedJob | null; onUploaded: (job: UploadedJob) => void }) {
  const [files, setFiles] = useState<File[]>([])
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [dragOver, setDragOver] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFiles = useCallback((newFiles: FileList | null) => {
    if (!newFiles) return
    const pcapFiles = Array.from(newFiles).filter(file => pcapFilenamePattern.test(file.name))
    if (pcapFiles.length === 0) {
      setError('请选择 .pcap、.pcap1、.pcapng 或 .cap 文件')
      return
    }
    setFiles(previous => [...previous, ...pcapFiles])
    setError(null)
  }, [])

  const handleUpload = useCallback(async () => {
    if (files.length === 0) return
    setUploading(true)
    setProgress(0)
    setError(null)

    const formData = new FormData()
    files.forEach(file => formData.append('files', file))

    try {
      const data = await uploadJob(formData, value => setProgress(value))
      onUploaded({
        id: data.job_id,
        fileCount: data.file_count,
        filename: files.map(file => file.name).join(', '),
      })
      setFiles([])
    } catch (err) {
      setError('上传失败: ' + (err as Error).message)
    } finally {
      setUploading(false)
    }
  }, [files, onUploaded])

  if (job) {
    return (
      <div className={`rounded-xl border px-4 py-3 shadow-sm ${side === 'left' ? 'border-teal-200 bg-teal-50' : 'border-sky-200 bg-sky-50'}`}>
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-white text-slate-700 shadow-sm">
            <FileArchive className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-black text-slate-950" title={job.filename}>{job.filename}</p>
            <p className="mt-1 text-xs font-bold text-slate-500">Job {job.id.slice(0, 8)} · {job.fileCount} 个文件</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div
        onClick={() => inputRef.current?.click()}
        onDragOver={event => { event.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={event => { event.preventDefault(); setDragOver(false); handleFiles(event.dataTransfer.files) }}
        className={`cursor-pointer rounded-xl border-2 border-dashed px-5 py-8 text-center transition ${
          dragOver ? 'border-teal-400 bg-teal-50' : 'border-slate-200 bg-white hover:border-teal-300 hover:bg-teal-50/40'
        }`}
      >
        <input ref={inputRef} type="file" multiple className="hidden" onChange={event => handleFiles(event.target.files)} />
        <UploadCloud className="mx-auto h-8 w-8 text-teal-600" />
        <p className="mt-3 text-sm font-black text-slate-950">导入{side === 'left' ? '左侧' : '右侧'}抓包</p>
        <p className="mt-1 text-xs font-semibold text-slate-500">支持多文件，会按任务合并处理</p>
      </div>

      {files.length > 0 && (
        <div className="mt-3 space-y-2">
          {files.map((file, index) => (
            <div key={`${file.name}:${index}`} className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm">
              <span className="min-w-0 truncate font-bold text-slate-700">{file.name}</span>
              {!uploading && (
                <button type="button" onClick={() => setFiles(previous => previous.filter((_, i) => i !== index))} className="rounded-md p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600">
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
          ))}
          {uploading ? (
            <div>
              <div className="h-2 overflow-hidden rounded-full bg-slate-100">
                <div className="h-full rounded-full bg-teal-600 transition-all" style={{ width: `${progress}%` }} />
              </div>
              <p className="mt-2 text-center text-xs font-black text-slate-500">上传中 {progress}%</p>
            </div>
          ) : (
            <button type="button" onClick={handleUpload} className="w-full rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-black text-white shadow-sm shadow-teal-600/20 hover:bg-teal-700">
              上传并创建任务
            </button>
          )}
        </div>
      )}

      {error && <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-bold text-rose-700">{error}</div>}
    </div>
  )
}

function SelectionSummary({ left, right, mismatch }: { left: ComparableMessage | null; right: ComparableMessage | null; mismatch: boolean }) {
  return (
    <div className="min-w-0 flex-1">
      <p className="text-sm font-black text-slate-950">当前选择</p>
      <div className="mt-2 grid grid-cols-1 gap-2 text-sm lg:grid-cols-2">
        <SelectedMessagePill label="左侧" message={left} />
        <SelectedMessagePill label="右侧" message={right} />
      </div>
      {mismatch && <p className="mt-2 text-sm font-bold text-amber-700">左右消息类型不同，不能进行字段差异对比</p>}
    </div>
  )
}

function SelectedMessagePill({ label, message }: { label: string; message: ComparableMessage | null }) {
  return (
    <div className="min-w-0 rounded-lg border border-slate-200 bg-white px-3 py-2 shadow-sm">
      <span className="text-xs font-black text-slate-500">{label}</span>
      {message ? (
        <span className="ml-2 font-black text-slate-950">Frame {message.frameNumber} · {message.typeLabel}</span>
      ) : (
        <span className="ml-2 font-bold text-slate-400">未选择</span>
      )}
    </div>
  )
}

interface ConnectorLine {
  id: string
  side: CaptureSide
  x1: number
  y1: number
  x2: number
  y2: number
}

function FourPaneDiffViewer({
  leftTree,
  rightTree,
  rows,
  hints,
  pasteInputOpen,
  pasteDrafts,
  pasteCompareError,
  onPasteDraftChange,
  onOpenPasteInput,
  onClosePasteInput,
  onComparePastedContent,
}: {
  leftTree: string
  rightTree: string
  rows: DiffRow[]
  hints: PositionHint[]
  pasteInputOpen: boolean
  pasteDrafts: Record<CaptureSide, string>
  pasteCompareError: string | null
  onPasteDraftChange: (side: CaptureSide, value: string) => void
  onOpenPasteInput: () => void
  onClosePasteInput: () => void
  onComparePastedContent: () => void
}) {
  const rootRef = useRef<HTMLDivElement | null>(null)
  const frameRef = useRef<number | null>(null)
  const leftAlignedScrollRef = useRef<HTMLDivElement | null>(null)
  const rightAlignedScrollRef = useRef<HTMLDivElement | null>(null)
  const syncingAlignedScrollRef = useRef(false)
  const [connectors, setConnectors] = useState<ConnectorLine[]>([])
  const [leftOriginalCollapsed, setLeftOriginalCollapsed] = useState(false)
  const [rightOriginalCollapsed, setRightOriginalCollapsed] = useState(false)
  const [alignedExpanded, setAlignedExpanded] = useState(false)
  const visibleHints = useMemo(() => hints.filter(hint => hintMovedOnSide(hint, 'left') || hintMovedOnSide(hint, 'right')).slice(0, 180), [hints])
  const leftLines = useMemo(() => splitTreeLines(leftTree), [leftTree])
  const rightLines = useMemo(() => splitTreeLines(rightTree), [rightTree])
  const leftHintIndexesByLine = useMemo(() => groupHintIndexesByLine(visibleHints, 'left'), [visibleHints])
  const rightHintIndexesByLine = useMemo(() => groupHintIndexesByLine(visibleHints, 'right'), [visibleHints])
  const leftHintIndexesByAlignedLine = useMemo(() => groupHintIndexesByAlignedLine(visibleHints, 'left'), [visibleHints])
  const rightHintIndexesByAlignedLine = useMemo(() => groupHintIndexesByAlignedLine(visibleHints, 'right'), [visibleHints])
  const leftOriginalHidden = alignedExpanded || leftOriginalCollapsed
  const rightOriginalHidden = alignedExpanded || rightOriginalCollapsed
  const gridTemplateColumns = [
    leftOriginalHidden ? '44px' : 'minmax(220px, 0.85fr)',
    'minmax(280px, 1.35fr)',
    'minmax(280px, 1.35fr)',
    rightOriginalHidden ? '44px' : 'minmax(220px, 0.85fr)',
  ].join(' ')

  const updateConnectors = useCallback(() => {
    const root = rootRef.current
    if (!root) return

    const nextConnectors: ConnectorLine[] = []
    visibleHints.forEach((_hint, index) => {
      const leftSource = connectorPoint(root, `left-source-${index}`)
      const leftTarget = connectorPoint(root, `left-target-${index}`)
      if (leftSource && leftTarget) {
        nextConnectors.push({ id: `left-${index}`, side: 'left', x1: leftSource.x, y1: leftSource.y, x2: leftTarget.x, y2: leftTarget.y })
      }

      const rightSource = connectorPoint(root, `right-source-${index}`)
      const rightTarget = connectorPoint(root, `right-target-${index}`)
      if (rightSource && rightTarget) {
        nextConnectors.push({ id: `right-${index}`, side: 'right', x1: rightSource.x, y1: rightSource.y, x2: rightTarget.x, y2: rightTarget.y })
      }
    })
    setConnectors(nextConnectors)
  }, [visibleHints])

  const scheduleConnectorUpdate = useCallback(() => {
    if (frameRef.current !== null) return
    frameRef.current = window.requestAnimationFrame(() => {
      frameRef.current = null
      updateConnectors()
    })
  }, [updateConnectors])

  const handleIndependentScroll = useCallback((_event: UIEvent<HTMLDivElement>) => {
    scheduleConnectorUpdate()
  }, [scheduleConnectorUpdate])

  const syncAlignedScroll = useCallback((side: CaptureSide, event: UIEvent<HTMLDivElement>) => {
    const source = event.currentTarget
    const target = side === 'left' ? rightAlignedScrollRef.current : leftAlignedScrollRef.current
    if (!target) {
      scheduleConnectorUpdate()
      return
    }
    if (syncingAlignedScrollRef.current) {
      scheduleConnectorUpdate()
      return
    }

    syncingAlignedScrollRef.current = true
    target.scrollTop = source.scrollTop
    target.scrollLeft = source.scrollLeft
    window.requestAnimationFrame(() => {
      syncingAlignedScrollRef.current = false
      scheduleConnectorUpdate()
    })
    scheduleConnectorUpdate()
  }, [scheduleConnectorUpdate])

  const handleLeftAlignedScroll = useCallback((event: UIEvent<HTMLDivElement>) => {
    syncAlignedScroll('left', event)
  }, [syncAlignedScroll])

  const handleRightAlignedScroll = useCallback((event: UIEvent<HTMLDivElement>) => {
    syncAlignedScroll('right', event)
  }, [syncAlignedScroll])

  const toggleLeftOriginal = useCallback(() => {
    setAlignedExpanded(false)
    setLeftOriginalCollapsed(previous => alignedExpanded ? false : !previous)
  }, [alignedExpanded])

  const toggleRightOriginal = useCallback(() => {
    setAlignedExpanded(false)
    setRightOriginalCollapsed(previous => alignedExpanded ? false : !previous)
  }, [alignedExpanded])

  const toggleAlignedExpanded = useCallback(() => {
    setAlignedExpanded(previous => !previous)
  }, [])

  useEffect(() => {
    scheduleConnectorUpdate()
    window.addEventListener('resize', scheduleConnectorUpdate)
    return () => {
      window.removeEventListener('resize', scheduleConnectorUpdate)
      if (frameRef.current !== null) {
        window.cancelAnimationFrame(frameRef.current)
      }
    }
  }, [scheduleConnectorUpdate])

  useEffect(() => {
    scheduleConnectorUpdate()
  }, [leftOriginalHidden, rightOriginalHidden, alignedExpanded, scheduleConnectorUpdate])

  return (
    <div ref={rootRef} className="relative h-[720px] overflow-hidden bg-slate-200/70">
      <div className="grid h-full min-h-0 gap-x-3" style={{ gridTemplateColumns }}>
        <OriginalTreePane
          title="左侧原始位置"
          side="left"
          lines={leftLines}
          hintIndexesByLine={leftHintIndexesByLine}
          collapsed={leftOriginalHidden}
          onToggleCollapse={toggleLeftOriginal}
          onScroll={handleIndependentScroll}
          className="border border-slate-200"
        />
        <AlignedPositionPane
          title="左侧对齐后"
          side="left"
          rows={rows}
          hintIndexesByAlignedLine={leftHintIndexesByAlignedLine}
          expanded={alignedExpanded}
          pasteInputOpen={pasteInputOpen}
          pasteValue={pasteDrafts.left}
          pasteCompareError={pasteCompareError}
          onToggleExpanded={toggleAlignedExpanded}
          onOpenPasteInput={onOpenPasteInput}
          onClosePasteInput={onClosePasteInput}
          onPasteChange={value => onPasteDraftChange('left', value)}
          onComparePastedContent={onComparePastedContent}
          scrollRef={leftAlignedScrollRef}
          onScroll={handleLeftAlignedScroll}
          className="border border-slate-200"
        />
        <AlignedPositionPane
          title="右侧对齐后"
          side="right"
          rows={rows}
          hintIndexesByAlignedLine={rightHintIndexesByAlignedLine}
          expanded={alignedExpanded}
          pasteInputOpen={pasteInputOpen}
          pasteValue={pasteDrafts.right}
          pasteCompareError={pasteCompareError}
          onToggleExpanded={toggleAlignedExpanded}
          onOpenPasteInput={onOpenPasteInput}
          onClosePasteInput={onClosePasteInput}
          onPasteChange={value => onPasteDraftChange('right', value)}
          onComparePastedContent={onComparePastedContent}
          scrollRef={rightAlignedScrollRef}
          onScroll={handleRightAlignedScroll}
          className="border border-slate-200"
        />
        <OriginalTreePane
          title="右侧原始位置"
          side="right"
          lines={rightLines}
          hintIndexesByLine={rightHintIndexesByLine}
          collapsed={rightOriginalHidden}
          onToggleCollapse={toggleRightOriginal}
          onScroll={handleIndependentScroll}
          className="border border-slate-200"
        />
      </div>
      <MergeConnectorOverlay connectors={connectors} />
    </div>
  )
}

function PaneFrame({ title, tone = 'plain', className = '', actions, scrollRef, onScroll, children }: { title: string; tone?: 'plain' | 'align'; className?: string; actions?: ReactNode; scrollRef?: Ref<HTMLDivElement>; onScroll: (event: UIEvent<HTMLDivElement>) => void; children: ReactNode }) {
  const headerClass = tone === 'align' ? 'bg-sky-50 text-sky-800' : 'bg-white text-slate-600'
  return (
    <div className={`flex h-full min-h-0 min-w-0 flex-col overflow-hidden bg-white ${className}`}>
      <div className={`flex shrink-0 items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 text-xs font-black ${headerClass}`}>
        <span className="min-w-0 truncate">{title}</span>
        {actions && <div className="flex shrink-0 items-center gap-1">{actions}</div>}
      </div>
      <div ref={scrollRef} data-scroll-pane className="min-h-0 flex-1 overscroll-contain overflow-x-auto overflow-y-scroll [scrollbar-gutter:stable]" onScroll={onScroll}>
        {children}
      </div>
    </div>
  )
}

function PaneIconButton({ title, onClick, children }: { title: string; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-slate-200 bg-white text-slate-500 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900"
    >
      {children}
    </button>
  )
}

function PaneTextButton({ title, onClick, children }: { title: string; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className="inline-flex h-7 items-center gap-1 rounded-md border border-slate-200 bg-white px-2 text-[11px] font-black text-slate-600 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900"
    >
      {children}
    </button>
  )
}

function CollapsedPane({ title, side, className = '', onExpand }: { title: string; side: CaptureSide; className?: string; onExpand: () => void }) {
  return (
    <div className={`flex h-full min-h-0 min-w-0 flex-col items-center overflow-hidden bg-white px-2 py-2 ${className}`}>
      <PaneIconButton title={`展开${title}`} onClick={onExpand}>
        {side === 'left' ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
      </PaneIconButton>
      <span className="mt-3 min-h-0 text-[11px] font-black text-slate-500 [writing-mode:vertical-rl]">{title}</span>
    </div>
  )
}

function OriginalTreePane({ title, side, lines, hintIndexesByLine, collapsed, className = '', onToggleCollapse, onScroll }: { title: string; side: CaptureSide; lines: string[]; hintIndexesByLine: Map<number, number[]>; collapsed: boolean; className?: string; onToggleCollapse: () => void; onScroll: (event: UIEvent<HTMLDivElement>) => void }) {
  if (collapsed) {
    return <CollapsedPane title={title} side={side} className={className} onExpand={onToggleCollapse} />
  }

  return (
    <PaneFrame
      title={title}
      className={className}
      actions={(
        <PaneIconButton title={`折叠${title}`} onClick={onToggleCollapse}>
          {side === 'left' ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </PaneIconButton>
      )}
      onScroll={onScroll}
    >
      {lines.map((line, index) => {
        const lineNumber = index + 1
        const hintIndexes = hintIndexesByLine.get(lineNumber) || []
        const hasHint = hintIndexes.length > 0
        return (
          <pre
            key={`${side}:raw:${lineNumber}`}
            className={`relative min-h-8 whitespace-pre border-b border-slate-100 py-2 pl-16 pr-4 font-mono text-xs leading-5 ${hasHint ? 'bg-blue-50 text-blue-950' : 'bg-white text-slate-700'}`}
          >
            <span className={`absolute top-2 w-10 text-right font-sans text-[10px] font-black ${hasHint ? 'text-blue-600' : 'text-slate-300'} ${side === 'left' ? 'left-2' : 'left-2'}`}>
              {lineNumber}
            </span>
            {hintIndexes.map(hintIndex => (
              <span
                key={`${side}:source:${hintIndex}`}
                data-connector={`${side}-source-${hintIndex}`}
                className={`absolute top-1/2 h-0 w-0 ${side === 'left' ? 'right-0' : 'left-0'}`}
              />
            ))}
            {line || ' '}
          </pre>
        )
      })}
    </PaneFrame>
  )
}

function AlignedPositionPane({
  title,
  side,
  rows,
  hintIndexesByAlignedLine,
  expanded,
  pasteInputOpen,
  pasteValue,
  pasteCompareError,
  className = '',
  scrollRef,
  onToggleExpanded,
  onOpenPasteInput,
  onClosePasteInput,
  onPasteChange,
  onComparePastedContent,
  onScroll,
}: {
  title: string
  side: CaptureSide
  rows: DiffRow[]
  hintIndexesByAlignedLine: Map<number, number[]>
  expanded: boolean
  pasteInputOpen: boolean
  pasteValue: string
  pasteCompareError: string | null
  className?: string
  scrollRef: Ref<HTMLDivElement>
  onToggleExpanded: () => void
  onOpenPasteInput: () => void
  onClosePasteInput: () => void
  onPasteChange: (value: string) => void
  onComparePastedContent: () => void
  onScroll: (event: UIEvent<HTMLDivElement>) => void
}) {
  return (
    <PaneFrame
      title={title}
      tone="align"
      className={className}
      actions={(
        <>
          {pasteInputOpen ? (
            <>
              <PaneTextButton title="对比左右复制内容" onClick={onComparePastedContent}>
                <FileDiff className="h-3.5 w-3.5" />
                对比
              </PaneTextButton>
              <PaneIconButton title="关闭内容输入" onClick={onClosePasteInput}>
                <X className="h-4 w-4" />
              </PaneIconButton>
            </>
          ) : (
            <PaneTextButton title="粘贴复制内容进行结构对比" onClick={onOpenPasteInput}>
              <ClipboardPaste className="h-3.5 w-3.5" />
              粘贴
            </PaneTextButton>
          )}
          <PaneIconButton title={expanded ? '恢复四栏宽度' : '横向扩展对齐区'} onClick={onToggleExpanded}>
            {expanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </PaneIconButton>
        </>
      )}
      scrollRef={scrollRef}
      onScroll={onScroll}
    >
      {pasteInputOpen ? (
        <PasteTextEditor side={side} value={pasteValue} error={pasteCompareError} onChange={onPasteChange} />
      ) : (
        rows.map((row, index) => {
          const alignedLineNumber = row.alignedLineNumber || index + 1
          const lineNumber = side === 'left' ? row.leftLineNumber : row.rightLineNumber
          const hintIndexes = hintIndexesByAlignedLine.get(alignedLineNumber) || []
          return (
            <pre
              key={`${side}:aligned:${index}:${row.kind}`}
              className={`relative min-h-8 whitespace-pre border-b border-slate-100 py-2 pl-16 pr-4 font-mono text-xs leading-5 ${diffCellClass(row.kind, side)}`}
            >
              {hintIndexes.map(hintIndex => (
                <span
                  key={`${side}:target:${hintIndex}`}
                  data-connector={`${side}-target-${hintIndex}`}
                  className={`absolute top-1/2 h-0 w-0 ${side === 'left' ? 'left-0' : 'right-0'}`}
                />
              ))}
              <span className={`absolute left-2 top-2 w-10 text-right font-sans text-[10px] font-black ${lineNumber ? 'text-blue-600' : 'text-slate-300'}`}>
                {lineNumber || ''}
              </span>
              {renderDiffContent(row, side) || ' '}
            </pre>
          )
        })
      )}
    </PaneFrame>
  )
}

function PasteTextEditor({ side, value, error, onChange }: { side: CaptureSide; value: string; error: string | null; onChange: (value: string) => void }) {
  return (
    <div className="flex min-h-full min-w-[360px] flex-col gap-3 bg-white p-3">
      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-black text-rose-700">
          {error}
        </div>
      )}
      <textarea
        value={value}
        onChange={event => onChange(event.target.value)}
        spellCheck={false}
        placeholder={`粘贴${side === 'left' ? '左侧' : '右侧'}复制内容，例如 Wireshark 协议树文本`}
        className="min-h-[610px] flex-1 resize-none rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-5 text-slate-800 outline-none focus:border-blue-300 focus:bg-white focus:ring-2 focus:ring-blue-100"
      />
    </div>
  )
}

function MergeConnectorOverlay({ connectors }: { connectors: ConnectorLine[] }) {
  return (
    <svg className="pointer-events-none absolute inset-0 z-20 h-full w-full">
      <defs>
        <marker id="packet-compare-left-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
          <path d="M 0 0 L 8 4 L 0 8 z" fill="#e11d48" />
        </marker>
        <marker id="packet-compare-right-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
          <path d="M 0 0 L 8 4 L 0 8 z" fill="#059669" />
        </marker>
      </defs>
      {connectors.map(connector => (
        <path
          key={connector.id}
          d={connectorPath(connector)}
          fill="none"
          stroke={connector.side === 'left' ? '#e11d48' : '#059669'}
          strokeLinecap="round"
          strokeWidth="2.5"
          markerEnd={`url(#packet-compare-${connector.side}-arrow)`}
          opacity="0.86"
        />
      ))}
    </svg>
  )
}

function groupHintIndexesByLine(hints: PositionHint[], side: CaptureSide) {
  const grouped = new Map<number, number[]>()
  hints.forEach((hint, index) => {
    if (!hintMovedOnSide(hint, side)) return
    const lineNumber = side === 'left' ? hint.leftLineNumber : hint.rightLineNumber
    const indexes = grouped.get(lineNumber)
    if (indexes) {
      indexes.push(index)
    } else {
      grouped.set(lineNumber, [index])
    }
  })
  return grouped
}

function groupHintIndexesByAlignedLine(hints: PositionHint[], side: CaptureSide) {
  const grouped = new Map<number, number[]>()
  hints.forEach((hint, index) => {
    if (!hintMovedOnSide(hint, side)) return
    const indexes = grouped.get(hint.alignedLineNumber)
    if (indexes) {
      indexes.push(index)
    } else {
      grouped.set(hint.alignedLineNumber, [index])
    }
  })
  return grouped
}

function hintMovedOnSide(hint: PositionHint, side: CaptureSide) {
  const sourceLineNumber = side === 'left' ? hint.leftLineNumber : hint.rightLineNumber
  return sourceLineNumber !== hint.alignedLineNumber
}

function connectorPoint(root: HTMLElement, connectorId: string) {
  const element = root.querySelector<HTMLElement>(`[data-connector="${connectorId}"]`)
  if (!element) return null
  const pane = element.closest<HTMLElement>('[data-scroll-pane]')
  if (!pane) return null

  const elementRect = element.getBoundingClientRect()
  const paneRect = pane.getBoundingClientRect()
  const rootRect = root.getBoundingClientRect()
  const visibleTop = Math.max(paneRect.top, rootRect.top)
  const visibleBottom = Math.min(paneRect.bottom, rootRect.bottom)
  const centerY = (elementRect.top + elementRect.bottom) / 2
  if (centerY < visibleTop || centerY > visibleBottom) return null

  return {
    x: (elementRect.left + elementRect.right) / 2 - rootRect.left,
    y: centerY - rootRect.top,
  }
}

function connectorPath({ x1, y1, x2, y2 }: ConnectorLine) {
  const direction = x2 >= x1 ? 1 : -1
  const distance = Math.abs(x2 - x1)
  const curve = Math.min(90, Math.max(12, distance * 0.45))
  return `M ${x1} ${y1} C ${x1 + direction * curve} ${y1}, ${x2 - direction * curve} ${y2}, ${x2} ${y2}`
}

function renderDiffContent(row: DiffRow, side: 'left' | 'right') {
  const segments = side === 'left' ? row.leftSegments : row.rightSegments
  const fallback = side === 'left' ? row.left : row.right
  if (!segments || segments.length === 0) return fallback || ''
  return segments.map((segment, index) => (
    <span key={index} className={segment.highlighted ? inlineDiffClass(side) : undefined}>
      {segment.text}
    </span>
  ))
}

function inlineDiffClass(side: 'left' | 'right') {
  return side === 'left'
    ? 'rounded bg-amber-200 px-0.5 font-black text-amber-950 ring-1 ring-amber-300/70'
    : 'rounded bg-emerald-200 px-0.5 font-black text-emerald-950 ring-1 ring-emerald-300/70'
}

function diffCellClass(kind: DiffKind, side: 'left' | 'right') {
  if (kind === 'same') return 'bg-white text-slate-600'
  if (kind === 'changed') return side === 'left' ? 'bg-amber-50 text-amber-900' : 'bg-emerald-50 text-emerald-900'
  if (kind === 'left') return side === 'left' ? 'bg-rose-50 text-rose-900' : 'bg-slate-50 text-slate-300'
  return side === 'right' ? 'bg-emerald-50 text-emerald-900' : 'bg-slate-50 text-slate-300'
}

function Badge({ children, className = 'border-slate-200 bg-slate-50 text-slate-600' }: { children: ReactNode; className?: string }) {
  return <span className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-black ${className}`}>{children}</span>
}

function SummaryPill({ label, value, title, className }: { label: string; value: number; title: string; className: string }) {
  return (
    <span title={title} className={`inline-flex rounded-lg border px-3 py-2 ${className}`}>
      {label}: {value}
    </span>
  )
}

function resetCaptureAnalysis(capture: CaptureState): CaptureState {
  return {
    ...capture,
    messages: [],
    loading: false,
    error: null,
    selectedId: null,
    query: '',
    typeFilter: 'all',
    page: 1,
  }
}

function selectedMessage(capture: CaptureState) {
  if (!capture.selectedId) return null
  return capture.messages.find(message => message.id === capture.selectedId) || null
}

function filterMessages(capture: CaptureState) {
  const query = capture.query.trim().toLowerCase()
  return capture.messages.filter(message => {
    if (capture.typeFilter !== 'all' && message.typeKey !== capture.typeFilter) return false
    if (!query) return true
    return [
      message.typeLabel,
      message.typeCode || '',
      message.directionLabel || '',
      message.context || '',
      message.sourceIp || '',
      message.destinationIp || '',
      String(message.frameNumber),
    ].some(value => value.toLowerCase().includes(query))
  })
}

function paginate<T>(items: T[], page: number) {
  const pageCount = Math.max(1, Math.ceil(items.length / PAGE_SIZE))
  const safePage = Math.min(Math.max(page, 1), pageCount)
  const start = (safePage - 1) * PAGE_SIZE
  return items.slice(start, start + PAGE_SIZE)
}

function buildTypeOptions(messages: ComparableMessage[]) {
  const grouped = new Map<string, { key: string; label: string; count: number }>()
  for (const message of messages) {
    const current = grouped.get(message.typeKey)
    if (current) {
      current.count += 1
    } else {
      grouped.set(message.typeKey, { key: message.typeKey, label: message.typeLabel, count: 1 })
    }
  }
  return Array.from(grouped.values()).sort((left, right) => {
    if (right.count !== left.count) return right.count - left.count
    return left.label.localeCompare(right.label)
  })
}

function formatProtocolSelectionLabel(configs: ProtocolConfig[]) {
  if (configs.length === protocolConfigs.length) return '全部协议'
  if (configs.length <= 3) return configs.map(item => item.label).join(' / ')
  return `${configs.slice(0, 3).map(item => item.label).join(' / ')} 等 ${configs.length} 个协议`
}

function displayProtocolLabel(protocol: ProtocolKey) {
  return protocolConfigs.find(item => item.key === protocol)?.label || protocol.toUpperCase()
}

async function fetchMessagesForProtocol(jobId: string, config: ProtocolConfig): Promise<{ config: ProtocolConfig; messages: ComparableMessage[] }> {
  const response = await fetch(`/api/jobs/${jobId}/${config.endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config.requestBody),
  })
  const data = (await response.json()) as APIResponse<any>
  if (!data.success || !data.data) {
    throw new Error(data.error || `${config.label} 消息分析失败`)
  }
  return {
    config,
    messages: config.normalize(data.data),
  }
}

async function uploadJob(formData: FormData, onProgress: (progress: number) => void): Promise<{ job_id: string; file_count: number }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()

    xhr.upload.onprogress = event => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 100))
      }
    }

    xhr.onload = () => {
      try {
        const data = JSON.parse(xhr.responseText) as APIResponse<{ job_id: string; file_count: number }>
        if (xhr.status === 200 && data.success && data.data) {
          resolve(data.data)
          return
        }
        reject(new Error(data.error || `HTTP ${xhr.status}`))
      } catch (err) {
        reject(err)
      }
    }

    xhr.onerror = () => reject(new Error('网络错误，请重试'))
    xhr.open('POST', '/api/jobs')
    xhr.send(formData)
  })
}

async function fetchPacketTree(jobId: string, message: ComparableMessage) {
  const response = await fetch(`/api/jobs/${jobId}/packets/${message.frameNumber}/tree?proto=${encodeURIComponent(message.treeProtocol)}`)
  const data = (await response.json()) as APIResponse<PacketTreeResponse>
  if (!data.success || !data.data) {
    throw new Error(data.error || `Frame ${message.frameNumber} 协议树获取失败`)
  }
  return data.data.tree
}

function createEmptyPasteComparison(): ComparisonResult {
  return {
    title: '复制内容结构对比',
    subtitle: '在中间两列粘贴左右复制内容后点击对比',
    leftTree: '',
    rightTree: '',
    rows: [],
    positionHints: [],
  }
}

function pastedInputToTree(source: string, label: string) {
  const trimmed = source.trim()
  if (!trimmed) {
    throw new Error(`${label} 不能为空`)
  }

  if (looksLikeJson(trimmed)) {
    try {
      return buildJsonTreeLines(JSON.parse(trimmed)).join('\n')
    } catch (err) {
      throw new Error(`${label} JSON 格式错误: ${(err as Error).message}`)
    }
  }

  return normalizePastedTreeText(trimmed)
}

function looksLikeJson(value: string) {
  return (value.startsWith('{') && value.endsWith('}')) || (value.startsWith('[') && value.endsWith(']'))
}

function normalizePastedTreeText(value: string) {
  return value
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map(line => line.replace(/\s+$/g, ''))
    .filter(line => line.trim() !== '')
    .join('\n')
}

function buildJsonTreeLines(value: unknown, label = 'JSON', depth = 0): string[] {
  const lines = [`${'  '.repeat(depth)}${formatJsonKey(label)}: ${pasteValueKind(value)}`]
  if (Array.isArray(value)) {
    for (const item of uniqueJsonArrayItems(value)) {
      lines.push(...buildJsonTreeLines(item, '[]', depth + 1))
    }
    return lines
  }
  if (isJsonObject(value)) {
    for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
      lines.push(...buildJsonTreeLines(value[key], key, depth + 1))
    }
  }
  return lines
}

function uniqueJsonArrayItems(items: unknown[]) {
  const seen = new Set<string>()
  const uniqueItems: unknown[] = []
  for (const item of items) {
    const signature = jsonStructureSignature(item)
    if (seen.has(signature)) continue
    seen.add(signature)
    uniqueItems.push(item)
  }
  return uniqueItems
}

function jsonStructureSignature(value: unknown): string {
  if (Array.isArray(value)) {
    const childSignatures = uniqueJsonArrayItems(value)
      .map(item => jsonStructureSignature(item))
      .sort()
      .join('|')
    return `array[${childSignatures}]`
  }
  if (isJsonObject(value)) {
    return `object{${Object.keys(value)
      .sort((left, right) => left.localeCompare(right))
      .map(key => `${formatJsonKey(key)}:${jsonStructureSignature(value[key])}`)
      .join(',')}}`
  }
  return pasteValueKind(value)
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function pasteValueKind(value: unknown) {
  if (Array.isArray(value)) return 'array'
  if (value === null) return 'null'
  return typeof value
}

function formatJsonKey(key: string) {
  return key.replace(/\s+/g, ' ').trim() || '""'
}

function buildLineDiff(leftTree: string, rightTree: string): StructureDiffResult {
  const leftLines = parseTreeLines(leftTree)
  const rightLines = parseTreeLines(rightTree)
  const rows: DiffRow[] = []

  let leftCursor = 0
  let rightCursor = 0
  const anchors = buildLcsMatchPairs(leftLines, rightLines)
  for (const anchor of anchors) {
    appendDiffBlock(rows, leftLines.slice(leftCursor, anchor.leftIndex), rightLines.slice(rightCursor, anchor.rightIndex))

    const left = leftLines[anchor.leftIndex]
    const right = rightLines[anchor.rightIndex]
    rows.push({ kind: 'same', left: left.line, right: right.line, leftLineNumber: left.index + 1, rightLineNumber: right.index + 1, alignedLineNumber: rows.length + 1 })

    leftCursor = anchor.leftIndex + 1
    rightCursor = anchor.rightIndex + 1
  }

  appendDiffBlock(rows, leftLines.slice(leftCursor), rightLines.slice(rightCursor))

  const alignedRows = reconcileMovedSameLevelRows(rows, leftLines, rightLines)
  const allRows = alignedRows.map((row, index) => ({
    ...row,
    alignedLineNumber: index + 1,
  }))
  const positionHints = buildPositionHintsFromRows(allRows, leftLines, rightLines)

  return { rows: allRows, positionHints }
}

function reconcileMovedSameLevelRows(rows: DiffRow[], leftLines: ParsedTreeLine[], rightLines: ParsedTreeLine[]) {
  const rightBlocksByMoveKey = new Map<string, SideOnlyBlock[]>()
  rows.forEach((row, rowIndex) => {
    if (row.kind !== 'right' || !row.rightLineNumber) return
    const line = rightLines[row.rightLineNumber - 1]
    if (!line || !canReconcileMovedStructureLine(line)) return
    const block = collectSideOnlyBlockRows(rows, rowIndex, rightLines, 'right')
    if (block) {
      appendSideOnlyBlock(rightBlocksByMoveKey, line.moveBlockKey, block)
    }
  })

  if (rightBlocksByMoveKey.size === 0) return rows

  const replacements = new Map<number, DiffRow[]>()
  const usedLeftRows = new Set<number>()
  const usedRightRows = new Set<number>()
  const removeRows = new Set<number>()

  rows.forEach((row, rowIndex) => {
    if (row.kind !== 'left' || !row.leftLineNumber || usedLeftRows.has(rowIndex)) return
    const left = leftLines[row.leftLineNumber - 1]
    if (!left) return

    if (!canReconcileMovedStructureLine(left)) return
    const leftBlock = collectSideOnlyBlockRows(rows, rowIndex, leftLines, 'left')
    if (!leftBlock || leftBlock.rowIndexes.some(index => usedLeftRows.has(index))) return

    const rightBlock = takeSideOnlyBlock(rightBlocksByMoveKey.get(left.moveBlockKey), usedRightRows)
    if (!rightBlock) return

    leftBlock.rowIndexes.forEach(index => {
      usedLeftRows.add(index)
      removeRows.add(index)
    })
    rightBlock.rowIndexes.forEach(index => {
      usedRightRows.add(index)
      removeRows.add(index)
    })
    replacements.set(leftBlock.startRowIndex, buildAlignedBlockRows(leftBlock.lines, rightBlock.lines))
  })

  if (replacements.size === 0) return rows

  const alignedRows: DiffRow[] = []
  rows.forEach((row, rowIndex) => {
    const replacement = replacements.get(rowIndex)
    if (replacement) {
      alignedRows.push(...replacement)
    }
    if (!removeRows.has(rowIndex)) {
      alignedRows.push(row)
    }
  })
  return alignedRows
}

interface SideOnlyBlock {
  startRowIndex: number
  rowIndexes: number[]
  lines: ParsedTreeLine[]
}

function appendSideOnlyBlock(grouped: Map<string, SideOnlyBlock[]>, key: string, block: SideOnlyBlock) {
  if (key === '') return
  const blocks = grouped.get(key)
  if (blocks) {
    blocks.push(block)
  } else {
    grouped.set(key, [block])
  }
}

function canReconcileMovedStructureLine(line: ParsedTreeLine) {
  const label = structureHintLabel(line.line)
  return line.blockEnd > line.index
    && isPositionHintStructureLine(line.line)
    && label !== ''
    && !isScalarStructureLabel(label)
}

function collectSideOnlyBlockRows(
  rows: DiffRow[],
  startRowIndex: number,
  lines: ParsedTreeLine[],
  side: 'left' | 'right',
): SideOnlyBlock | null {
  const lineNumberKey = side === 'left' ? 'leftLineNumber' : 'rightLineNumber'
  const startLineNumber = rows[startRowIndex][lineNumberKey]
  if (!startLineNumber) return null

  const startLine = lines[startLineNumber - 1]
  if (!startLine) return null

  const blockLines: ParsedTreeLine[] = []
  const rowIndexes: number[] = []
  const endLineNumber = startLine.blockEnd + 1
  for (let lineNumber = startLineNumber; lineNumber <= endLineNumber; lineNumber += 1) {
    const rowIndex = startRowIndex + lineNumber - startLineNumber
    const row = rows[rowIndex]
    const line = lines[lineNumber - 1]
    if (!row || row.kind !== side || row[lineNumberKey] !== lineNumber || !line) {
      return null
    }
    rowIndexes.push(rowIndex)
    blockLines.push(line)
  }
  return { startRowIndex, rowIndexes, lines: blockLines }
}

function takeSideOnlyBlock(candidates: SideOnlyBlock[] | undefined, usedRightRows: Set<number>) {
  if (!candidates) return null
  return candidates.find(candidate => !candidate.rowIndexes.some(rowIndex => usedRightRows.has(rowIndex))) || null
}

function buildAlignedBlockRows(leftBlock: ParsedTreeLine[], rightBlock: ParsedTreeLine[]) {
  const rows: DiffRow[] = []
  const rowCount = Math.max(leftBlock.length, rightBlock.length)
  for (let index = 0; index < rowCount; index += 1) {
    const left = leftBlock[index]
    const right = rightBlock[index]
    if (left && right) {
      rows.push(buildChangedRow(left.line, right.line, left.index + 1, right.index + 1))
    } else if (left) {
      rows.push({ kind: 'left', left: left.line, leftLineNumber: left.index + 1 })
    } else if (right) {
      rows.push({ kind: 'right', right: right.line, rightLineNumber: right.index + 1 })
    }
  }
  return rows
}

function buildPositionHintsFromRows(rows: DiffRow[], leftLines: ParsedTreeLine[], rightLines: ParsedTreeLine[]) {
  const hints: PositionHint[] = []
  rows.forEach((row, index) => {
    if (!row.leftLineNumber || !row.rightLineNumber) return
    const left = leftLines[row.leftLineNumber - 1]
    const right = rightLines[row.rightLineNumber - 1]
    if (!left || !right) return
    if (shouldShowPositionHint(left, right)) {
      hints.push(buildPositionHint(left, right, index + 1))
    }
  })
  return hints
}

function buildLcsMatchPairs(leftLines: ParsedTreeLine[], rightLines: ParsedTreeLine[]) {
  const width = rightLines.length + 1
  const dp = new Uint32Array((leftLines.length + 1) * width)

  for (let leftIndex = leftLines.length - 1; leftIndex >= 0; leftIndex -= 1) {
    for (let rightIndex = rightLines.length - 1; rightIndex >= 0; rightIndex -= 1) {
      const offset = leftIndex * width + rightIndex
      if (linesMatchForAnchor(leftLines[leftIndex], rightLines[rightIndex])) {
        dp[offset] = dp[(leftIndex + 1) * width + rightIndex + 1] + 1
      } else {
        dp[offset] = Math.max(dp[(leftIndex + 1) * width + rightIndex], dp[leftIndex * width + rightIndex + 1])
      }
    }
  }

  const pairs: Array<{ leftIndex: number; rightIndex: number }> = []
  let leftIndex = 0
  let rightIndex = 0
  while (leftIndex < leftLines.length && rightIndex < rightLines.length) {
    if (linesMatchForAnchor(leftLines[leftIndex], rightLines[rightIndex])) {
      pairs.push({ leftIndex, rightIndex })
      leftIndex += 1
      rightIndex += 1
    } else if (dp[(leftIndex + 1) * width + rightIndex] >= dp[leftIndex * width + rightIndex + 1]) {
      leftIndex += 1
    } else {
      rightIndex += 1
    }
  }
  return pairs
}

function linesMatchForAnchor(left: ParsedTreeLine, right: ParsedTreeLine) {
  return left.anchorKey !== '' && left.anchorKey === right.anchorKey
}

function appendDiffBlock(rows: DiffRow[], leftBlock: ParsedTreeLine[], rightBlock: ParsedTreeLine[]) {
  if (leftBlock.length === 0 && rightBlock.length === 0) return

  const rightByFamily = groupTreeLinesByKey(rightBlock, line => line.familyKey)
  const initialMatches = leftBlock.map(left => ({
    left,
    right: rightByFamily.get(left.familyKey)?.shift(),
  }))
  let lastAcceptedRightIndex = -1
  const matches = initialMatches.map(match => {
    if (!match.right) return match
    if (match.right.index < lastAcceptedRightIndex) {
      return { ...match, right: undefined }
    }
    lastAcceptedRightIndex = Math.max(lastAcceptedRightIndex, match.right.index)
    return match
  })
  const matchedRight = new Set(matches.flatMap(match => match.right ? [match.right.index] : []))
  let rightCursor = 0

  const appendUnmatchedRightBefore = (rightIndex: number) => {
    while (rightCursor < rightBlock.length && rightBlock[rightCursor].index < rightIndex) {
      const right = rightBlock[rightCursor]
      if (!matchedRight.has(right.index)) {
        rows.push({ kind: 'right', right: right.line, rightLineNumber: right.index + 1 })
      }
      rightCursor += 1
    }
  }
  const advanceRightCursorThrough = (rightIndex: number) => {
    while (rightCursor < rightBlock.length && rightBlock[rightCursor].index <= rightIndex) {
      rightCursor += 1
    }
  }

  matches.forEach(({ left, right }, matchIndex) => {
    if (right) {
      appendUnmatchedRightBefore(right.index)
      rows.push(buildChangedRow(left.line, right.line, left.index + 1, right.index + 1))
      advanceRightCursorThrough(right.index)

      const nextRight = matches.slice(matchIndex + 1).find(match => match.right)?.right
      const activeBlockEnd = Math.max(right.blockEnd, right.containingBlockEnd)
      if (activeBlockEnd > right.index && (!nextRight || nextRight.index < right.index || nextRight.index > activeBlockEnd)) {
        appendUnmatchedRightBefore(activeBlockEnd + 1)
      }
    } else {
      rows.push({ kind: 'left', left: left.line, leftLineNumber: left.index + 1 })
    }
  })

  appendUnmatchedRightBefore(Number.POSITIVE_INFINITY)
}

function parseTreeLines(tree: string): ParsedTreeLine[] {
  const stack: Array<{ indent: number; key: string }> = []
  const lines = splitTreeLines(tree).map((line, index) => {
    const indent = indentWidth(line)
    const content = normalizedStructureContentFromLine(line)
    const family = structureFamilyContent(content)
    while (stack.length > 0 && stack[stack.length - 1].indent >= indent) {
      stack.pop()
    }
    const parentPath = stack.map(item => item.key).join('>')
    const key = `${indent}|${parentPath}>${content}`
    const familyKey = `${indent}|${parentPath}>${family}`
    const moveBlockKey = structureMoveBlockKey(line, family, indent)
    const anchorKey = structureAnchorKey(line, content, family, indent, parentPath)
    if (content !== '') {
      stack.push({ indent, key: content })
    }
    return { line, key, familyKey, moveBlockKey, anchorKey, index, indent, blockEnd: index, containingBlockEnd: index }
  })

  lines.forEach((line, index) => {
    let endIndex = index
    while (endIndex + 1 < lines.length && lines[endIndex + 1].indent > line.indent) {
      endIndex += 1
    }
    line.blockEnd = endIndex
  })

  const blockStack: Array<{ indent: number; blockEnd: number }> = []
  lines.forEach(line => {
    while (blockStack.length > 0 && (blockStack[blockStack.length - 1].indent >= line.indent || blockStack[blockStack.length - 1].blockEnd < line.index)) {
      blockStack.pop()
    }
    line.containingBlockEnd = blockStack[blockStack.length - 1]?.blockEnd ?? line.index
    if (line.blockEnd > line.index) {
      blockStack.push({ indent: line.indent, blockEnd: line.blockEnd })
    }
  })

  return lines
}

function structureAnchorKey(line: string, content: string, family: string, indent: number, parentPath: string) {
  const trimmed = line.trim()
  if (content === '' || family === '') return ''
  if (trimmed.includes(' = ')) return ''
  if (isScalarStructureLabel(family) || isScalarStructureLabel(content)) return ''
  if (/^(?:\.*[01]\.*\s*)+[=:]/.test(trimmed)) return ''
  return `${indent}|${parentPath}>${family}`
}

function structureMoveBlockKey(line: string, family: string, indent: number) {
  const label = structureHintLabel(line)
  if (family === '' || label === '' || isScalarStructureLabel(label) || isScalarStructureLabel(family)) return ''
  return `${indent}|${family}`
}

function groupTreeLinesByKey(lines: ParsedTreeLine[], keyFn: (line: ParsedTreeLine) => string = line => line.key) {
  const grouped = new Map<string, ParsedTreeLine[]>()
  for (const line of lines) {
    const key = keyFn(line)
    const group = grouped.get(key)
    if (group) {
      group.push(line)
    } else {
      grouped.set(key, [line])
    }
  }
  return grouped
}

function shouldShowPositionHint(left: ParsedTreeLine, right: ParsedTreeLine) {
  if (left.index === right.index) return false
  if (!isPositionHintStructureLine(left.line)) return false
  const label = structureHintLabel(left.line)
  if (label === '') return false
  if (isScalarStructureLabel(label)) return false
  return Math.abs(left.index - right.index) >= 3
}

function isPositionHintStructureLine(line: string) {
  const trimmed = line.trim()
  if (trimmed === '') return false
  if (trimmed.includes(' = ')) return false
  const content = normalizedStructureContentFromLine(line)
  const label = structureHintLabel(line)
  if (isScalarStructureLabel(label) || isScalarStructureLabel(content)) return false
  if (/^(?:\.*[01]\.*\s*)+[=:]/.test(trimmed)) return false
  if (/:\s*(?:0x[0-9a-fA-F]+|-?\d+|\d{1,3}(?:\.\d{1,3}){3})\b/.test(trimmed)) return false
  return trimmed.endsWith(':')
    || trimmed.includes('[Grouped IE]')
    || /^(Item|ProtocolIE|IE|AVP|Create|Update|Remove|Forwarding|Outer Header|SDF|UE IP|Network Instance|Bearer|PDU Session|QoS|Transport|Security|Authentication|Registration|Service|Attach|Detach|Handover|Setup|Release|Modification|Establishment|Initial|Uplink|Downlink|NAS|GTP|NGAP|S1AP)\b/i.test(trimmed)
    || /\b(PDU|Message|Field|Container|Context|Request|Response|Command|Accept|Reject|Identity|Information|Parameters|List)\b/i.test(trimmed)
}

function buildPositionHint(left: ParsedTreeLine, right: ParsedTreeLine, alignedLineNumber: number): PositionHint {
  return {
    id: `${left.index}:${right.index}:${left.key}`,
    label: structureHintLabel(left.line),
    leftLine: left.line,
    rightLine: right.line,
    leftLineNumber: left.index + 1,
    rightLineNumber: right.index + 1,
    alignedLineNumber,
  }
}

function structureHintLabel(line: string) {
  const content = normalizedStructureContentFromLine(line)
  const colonIndex = content.indexOf(':')
  if (colonIndex > 0) {
    return content.slice(0, colonIndex).trim()
  }
  return content.trim()
}

function indentWidth(line: string) {
  return (line.match(/^\s*/)?.[0] || '').replace(/\t/g, '    ').length
}

function normalizedStructureContentFromLine(line: string) {
  let content = line.trim()
  const equalsIndex = content.indexOf(' = ')
  if (equalsIndex >= 0) {
    content = content.slice(equalsIndex + 3).trim()
  }
  return canonicalStructureContent(normalizeStructureContent(content))
}

function structureFamilyContent(content: string) {
  if (/^(IE Type|Message Type|Procedure|Packet Forwarding Control Protocol|S1 Application Protocol|NG Application Protocol|GPRS Tunneling Protocol|Non-Access-Stratum|NAS-5GS|NAS-EPS|Diameter Protocol)\b/i.test(content)) {
    return content
  }
  const spacedColonIndex = content.indexOf(' : ')
  if (spacedColonIndex >= 0) {
    return content.slice(0, spacedColonIndex).trim()
  }
  const colonIndex = content.indexOf(':')
  if (colonIndex > 0) {
    return content.slice(0, colonIndex).trim()
  }
  return content
}

function canonicalStructureContent(content: string) {
  const firstToken = content.split(/[,:]/, 1)[0]?.trim().toLowerCase()
  if (firstToken === 'flag' || firstToken === 'flags') return 'Flags'

  const colonIndex = content.indexOf(':')
  if (colonIndex <= 0) return content

  const label = content.slice(0, colonIndex).trim()
  const value = content.slice(colonIndex + 1).trim()
  if (shouldPreserveColonValue(label, value, content)) {
    return content
  }
  return label
}

function shouldPreserveColonValue(label: string, value: string, content: string) {
  if (value === '') return false
  if (/^(IE Type|Message Type|Procedure|NGAP-PDU|S1AP-PDU|GTPv2 Message Type|GTP Message Type|NAS Message Type)$/i.test(label)) return true
  if (/^Item\b/i.test(label) && !/^(?:0x[0-9a-fA-F]+|-?\d+|\d{1,3}(?:\.\d{1,3}){3})$/.test(value)) return true
  if (/^\[[^\]]+\]$/.test(value)) return true
  if (content.includes('[Grouped IE]')) return true
  return false
}

function isScalarStructureLabel(label: string) {
  return /^(?:IE Length|Length|Flags?|Spare|Sequence Number|Seq(?:uence)?|SEID|TEID|GRE Key|IPv4|IPv6|IP Address|Port|Rule ID|PDR ID|FAR ID|QER ID|URR ID|Bearer ID|EPS Bearer ID|EBI|QFI|RAB ID|E-RAB ID|DRB ID|RAN UE NGAP ID|AMF UE NGAP ID|MME UE S1AP ID|eNB UE S1AP ID|ENB UE S1AP ID|gNB CU UE F1AP ID|gNB DU UE F1AP ID|Procedure Code|Criticality|Presence|ID|Value|Cause|TAC|MCC|MNC|PLMN|Cell Identity|ECGI|NCGI|TAI|GUMMEI|GUAMI|TMSI|5G-TMSI|M-TMSI|IMSI|SUCI|SUPI|MSIN|IMEI|IMEISV|APN|DNN|S-NSSAI|SST|SD|PTI|PDU Session ID|Message Authentication Code|NAS Key Set Identifier|Security Header Type|Protocol Discriminator|Access Type|Direction|Priority|Precedence|Delay|Timestamp|Time|Counter|Mask|Offset|Size|Checksum|Window|Stream identifier|Verification tag)\b/i.test(label.trim())
}

function normalizeStructureContent(content: string) {
  return content
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '')
    .replace(/\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,}\b/g, '')
    .replace(/\b0x[0-9a-fA-F]+\b/g, '')
    .replace(/\b(?:true|false|True|False)\b/g, '')
    .replace(/\b(?:present|not present|Present|Not Present)\b/g, '')
    .replace(/(^|[^A-Za-z0-9_-])-?\d+(?:\.\d+)?(?=$|[^A-Za-z0-9_-])/g, '$1')
    .replace(/\(\s*\)/g, '')
    .replace(/\[\s*\]/g, '')
    .replace(/\s*,\s*,+/g, ', ')
    .replace(/:\s*(?=,|$)/g, '')
    .replace(/,\s*$/g, '')
    .replace(/\s+/g, ' ')
    .trim()
}

function buildChangedRow(left: string, right: string, leftLineNumber?: number, rightLineNumber?: number): DiffRow {
  if (normalizedStructureContentFromLine(left) === normalizedStructureContentFromLine(right)) {
    return { kind: 'same', left, right, leftLineNumber, rightLineNumber }
  }
  const [leftSegments, rightSegments] = buildInlineDiff(left, right)
  return { kind: 'changed', left, right, leftLineNumber, rightLineNumber, leftSegments, rightSegments }
}

function buildInlineDiff(left: string, right: string): [DiffSegment[], DiffSegment[]] {
  if (left === right) {
    return [[{ text: left, highlighted: false }], [{ text: right, highlighted: false }]]
  }
  if (left.length * right.length > 120000) {
    return buildBoundaryInlineDiff(left, right)
  }

  const dp = Array.from({ length: left.length + 1 }, () => new Array<number>(right.length + 1).fill(0))
  for (let i = left.length - 1; i >= 0; i -= 1) {
    for (let j = right.length - 1; j >= 0; j -= 1) {
      dp[i][j] = left[i] === right[j]
        ? dp[i + 1][j + 1] + 1
        : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }

  const leftSegments: DiffSegment[] = []
  const rightSegments: DiffSegment[] = []
  let i = 0
  let j = 0
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) {
      appendSegment(leftSegments, left[i], false)
      appendSegment(rightSegments, right[j], false)
      i += 1
      j += 1
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      appendSegment(leftSegments, left[i], true)
      i += 1
    } else {
      appendSegment(rightSegments, right[j], true)
      j += 1
    }
  }
  while (i < left.length) {
    appendSegment(leftSegments, left[i], true)
    i += 1
  }
  while (j < right.length) {
    appendSegment(rightSegments, right[j], true)
    j += 1
  }

  return [leftSegments, rightSegments]
}

function buildBoundaryInlineDiff(left: string, right: string): [DiffSegment[], DiffSegment[]] {
  let prefixLength = 0
  while (
    prefixLength < left.length &&
    prefixLength < right.length &&
    left[prefixLength] === right[prefixLength]
  ) {
    prefixLength += 1
  }

  let suffixLength = 0
  while (
    suffixLength < left.length - prefixLength &&
    suffixLength < right.length - prefixLength &&
    left[left.length - 1 - suffixLength] === right[right.length - 1 - suffixLength]
  ) {
    suffixLength += 1
  }

  const leftSegments = boundarySegments(left, prefixLength, suffixLength)
  const rightSegments = boundarySegments(right, prefixLength, suffixLength)
  return [leftSegments, rightSegments]
}

function boundarySegments(value: string, prefixLength: number, suffixLength: number): DiffSegment[] {
  const middleEnd = value.length - suffixLength
  return [
    { text: value.slice(0, prefixLength), highlighted: false },
    { text: value.slice(prefixLength, middleEnd), highlighted: true },
    { text: value.slice(middleEnd), highlighted: false },
  ].filter(segment => segment.text !== '')
}

function appendSegment(segments: DiffSegment[], text: string, highlighted: boolean) {
  const previous = segments[segments.length - 1]
  if (previous && previous.highlighted === highlighted) {
    previous.text += text
    return
  }
  segments.push({ text, highlighted })
}

function splitTreeLines(tree: string) {
  return tree.replace(/\r\n/g, '\n').split('\n').map(line => line.replace(/\s+$/g, ''))
}

function getDiffStats(rows: DiffRow[]) {
  return rows.reduce((stats, row) => {
    stats[row.kind] += 1
    return stats
  }, { same: 0, changed: 0, left: 0, right: 0 } as Record<DiffKind, number>)
}

function normalizeNGAPMessages(data: any): ComparableMessage[] {
  return (data.messages || []).map((message: any) => ({
    id: `ngap:${message.id || message.frame_number}`,
    protocol: 'ngap',
    treeProtocol: 'ngap',
    frameNumber: Number(message.frame_number),
    timestamp: message.timestamp,
    sourceIp: message.source_ip,
    destinationIp: message.destination_ip,
    typeKey: `ngap:${message.procedure_code}:${message.pdu_type}`,
    typeLabel: `${message.procedure_name || 'NGAP'} / ${pduLabel(message.pdu_type)}`,
    typeCode: `Procedure ${message.procedure_code}`,
    directionLabel: ngapDirectionLabel(message.direction),
    context: compactParts([
      message.ran_ue_ngap_id ? `RAN ${message.ran_ue_ngap_id}` : '',
      message.amf_ue_ngap_id ? `AMF ${message.amf_ue_ngap_id}` : '',
      message.has_nas ? '携带 NAS' : '',
    ]),
    filter: message.wireshark_filter,
  }))
}

function normalizeS1APMessages(data: any): ComparableMessage[] {
  return (data.messages || []).map((message: any) => ({
    id: `s1ap:${message.id || message.frame_number}`,
    protocol: 's1ap',
    treeProtocol: 's1ap',
    frameNumber: Number(message.frame_number),
    timestamp: message.timestamp,
    sourceIp: message.source_ip,
    destinationIp: message.destination_ip,
    typeKey: `s1ap:${message.procedure_code}:${message.pdu_type}`,
    typeLabel: `${message.procedure_name || 'S1AP'} / ${pduLabel(message.pdu_type)}`,
    typeCode: `Procedure ${message.procedure_code}`,
    directionLabel: s1apDirectionLabel(message.direction),
    context: compactParts([
      message.enb_ue_s1ap_id ? `eNB ${message.enb_ue_s1ap_id}` : '',
      message.mme_ue_s1ap_id ? `MME ${message.mme_ue_s1ap_id}` : '',
      message.erab_id ? `E-RAB ${message.erab_id}` : '',
      message.has_nas ? '携带 NAS' : '',
    ]),
    filter: message.wireshark_filter,
  }))
}

function normalizeNASMessages(data: any): ComparableMessage[] {
  return (data.messages || []).map((message: any) => ({
    id: `nas:${message.id || message.frame_number}`,
    protocol: 'nas',
    treeProtocol: 'nas-5gs',
    frameNumber: Number(message.frame_number),
    timestamp: message.timestamp,
    sourceIp: message.source_ip,
    destinationIp: message.destination_ip,
    typeKey: `nas:${message.category}:${message.message_type_code}`,
    typeLabel: `${nasCategoryLabel(message.category)} ${message.message_type || 'NAS'}`,
    typeCode: `Type ${message.message_type_code}`,
    directionLabel: nasDirectionLabel(message.direction),
    context: compactParts([
      message.security_header_name || '',
      message.sequence_number ? `SQN ${message.sequence_number}` : '',
      message.ngap_procedure_code ? `NGAP ${message.ngap_procedure_code}` : '',
    ]),
    filter: message.wireshark_filter,
  }))
}

function normalizeSMNASMessages(data: any): ComparableMessage[] {
  return (data.messages || []).map((message: any) => ({
    id: `sm-nas:${message.id || message.frame_number}`,
    protocol: 'sm-nas',
    treeProtocol: 'nas-5gs',
    frameNumber: Number(message.frame_number),
    timestamp: message.timestamp,
    sourceIp: message.source_ip,
    destinationIp: message.destination_ip,
    typeKey: `sm-nas:${message.message_type_code}`,
    typeLabel: `5GSM ${message.message_type || 'SM NAS'}`,
    typeCode: `Type ${message.message_type_code}`,
    directionLabel: nasDirectionLabel(message.direction),
    context: compactParts([
      message.security_header_name || '',
      message.sequence_number ? `SQN ${message.sequence_number}` : '',
      message.ngap_procedure_code ? `NGAP ${message.ngap_procedure_code}` : '',
    ]),
    filter: message.wireshark_filter,
  }))
}

function normalizeS11Messages(data: any): ComparableMessage[] {
  const rows: ComparableMessage[] = []
  for (const tx of data.transactions || []) {
    rows.push({
      id: `s11:req:${tx.id || tx.sequence_number}:${tx.request_frame}`,
      protocol: 's11',
      treeProtocol: 'gtpv2',
      frameNumber: Number(tx.request_frame),
      timestamp: tx.request_time,
      sourceIp: tx.source_ip,
      destinationIp: tx.destination_ip,
      typeKey: `s11:${tx.request_type || tx.procedure}:request`,
      typeLabel: tx.request_type || `${tx.procedure} Request`,
      typeCode: `Seq ${tx.sequence_number}`,
      directionLabel: 'Request',
      context: compactParts([tx.procedure, tx.request_teid ? `TEID ${tx.request_teid}` : '', tx.apn || '']),
      filter: tx.wireshark_filter,
    })
    if (tx.response_frame) {
      rows.push({
        id: `s11:rsp:${tx.id || tx.sequence_number}:${tx.response_frame}`,
        protocol: 's11',
        treeProtocol: 'gtpv2',
        frameNumber: Number(tx.response_frame),
        timestamp: tx.response_time,
        sourceIp: tx.destination_ip,
        destinationIp: tx.source_ip,
        typeKey: `s11:${tx.response_type || tx.procedure}:response`,
        typeLabel: tx.response_type || `${tx.procedure} Response`,
        typeCode: `Seq ${tx.sequence_number}`,
        directionLabel: 'Response',
        context: compactParts([tx.cause_name || tx.cause || '', tx.response_teid ? `TEID ${tx.response_teid}` : '', tx.apn || '']),
        filter: tx.wireshark_filter,
      })
    }
  }
  return rows
}

function normalizePFCPMessages(data: any): ComparableMessage[] {
  const rows: ComparableMessage[] = []
  for (const tx of data.transactions || []) {
    const requestCode = Number(tx.message_type_code)
    rows.push({
      id: `pfcp:req:${tx.id || tx.sequence_number}:${tx.request_frame}`,
      protocol: 'pfcp',
      treeProtocol: 'pfcp',
      frameNumber: Number(tx.request_frame),
      timestamp: tx.request_time,
      sourceIp: tx.source_ip,
      destinationIp: tx.destination_ip,
      typeKey: `pfcp:${requestCode}:request`,
      typeLabel: `${tx.message_type || 'PFCP'} Request`,
      typeCode: `Type ${requestCode}`,
      directionLabel: 'Request',
      context: compactParts([`Seq ${tx.sequence_number}`, tx.request_seid ? `SEID ${tx.request_seid}` : '']),
      filter: tx.wireshark_filter,
    })
    if (tx.response_frame) {
      rows.push({
        id: `pfcp:rsp:${tx.id || tx.sequence_number}:${tx.response_frame}`,
        protocol: 'pfcp',
        treeProtocol: 'pfcp',
        frameNumber: Number(tx.response_frame),
        timestamp: tx.response_time,
        sourceIp: tx.destination_ip,
        destinationIp: tx.source_ip,
        typeKey: `pfcp:${requestCode + 1}:response`,
        typeLabel: `${tx.message_type || 'PFCP'} Response`,
        typeCode: `Type ${requestCode + 1}`,
        directionLabel: 'Response',
        context: compactParts([`Seq ${tx.sequence_number}`, tx.cause_name || '', tx.response_seid ? `SEID ${tx.response_seid}` : '']),
        filter: tx.wireshark_filter,
      })
    }
  }
  return rows
}

function pduLabel(value?: string) {
  const labels: Record<string, string> = {
    initiating: '发起',
    successful_outcome: '成功结果',
    unsuccessful_outcome: '失败结果',
    unknown: '未知 PDU',
  }
  return labels[value || ''] || value || 'PDU'
}

function ngapDirectionLabel(value?: string) {
  const labels: Record<string, string> = {
    gnb_to_amf: 'gNB -> AMF',
    amf_to_gnb: 'AMF -> gNB',
    unknown: '未知方向',
  }
  return labels[value || ''] || value
}

function s1apDirectionLabel(value?: string) {
  const labels: Record<string, string> = {
    enb_to_mme: 'eNB -> MME',
    mme_to_enb: 'MME -> eNB',
    unknown: '未知方向',
  }
  return labels[value || ''] || value
}

function nasDirectionLabel(value?: string) {
  const labels: Record<string, string> = {
    uplink: '上行',
    downlink: '下行',
    unknown: '未知方向',
  }
  return labels[value || ''] || value
}

function nasCategoryLabel(value?: string) {
  const labels: Record<string, string> = {
    '5gmm': '5GMM',
    '5gsm': '5GSM',
  }
  return labels[value || ''] || value || 'NAS'
}

function compactParts(parts: Array<string | undefined | null>) {
  return parts.filter(part => part && String(part).trim() !== '').join(' · ')
}

function formatTimestamp(value?: string) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const base = date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  return `${base}.${String(date.getMilliseconds()).padStart(3, '0')}`
}
