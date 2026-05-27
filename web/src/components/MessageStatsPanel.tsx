import { startTransition, useCallback, useEffect, useMemo, useState } from 'react'
import { BarChart3, ChevronDown, Download, Loader2, RefreshCw, Sigma } from 'lucide-react'
import { readEventStream } from '../utils/eventStream'

interface MessageStatsPanelProps {
  jobId: string
  selectedIMSIs: string[]
}

interface StatsItem {
  key: string
  name: string
  filter: string
  raw_count: number
  correction: number
  count: number
  correction_reason?: string
}

interface StatsModule {
  key: string
  name: string
  standard?: string
  raw_total: number
  final_total: number
  items: StatsItem[]
}

interface MessageStatsResult {
  scope_filter?: string
  truncated?: boolean
  row_limit?: number
  modules: StatsModule[]
}

interface StreamProgress {
  processed_rows?: number
  chunk_index?: number
  chunk_rows?: number
  chunk_target?: number
  done?: boolean
}

interface StreamPayload<T> {
  progress?: StreamProgress
  result?: T
  cached?: boolean
}

export function MessageStatsPanel({ jobId, selectedIMSIs: _selectedIMSIs }: MessageStatsPanelProps) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<MessageStatsResult | null>(null)
  const [progress, setProgress] = useState<StreamProgress | null>(null)
  const [activeModuleKey, setActiveModuleKey] = useState<string>('')
  const [error, setError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => {
    setResult(null)
    setProgress(null)
    setActiveModuleKey('')
    setError(null)
  }, [jobId])

  const handleLoadStats = useCallback(async () => {
    if (loading) return
    setLoading(true)
    setError(null)
    setProgress(null)

    try {
      const response = await fetch(`/api/jobs/${jobId}/message-stats/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ batch_rows: 5000 }),
      })
      await readEventStream<StreamPayload<MessageStatsResult> | string>(response, ({ event, data }) => {
        if (event === 'error') {
          throw new Error(typeof data === 'string' ? data : '消息统计失败')
        }
        if (event === 'progress' && typeof data === 'object') {
          setProgress((data as StreamPayload<MessageStatsResult>).progress || {})
          return
        }
        if ((event === 'partial_result' || event === 'done') && typeof data === 'object') {
          const payload = data as StreamPayload<MessageStatsResult>
          if (payload.progress) setProgress(payload.progress)
          if (payload.result) {
            startTransition(() => {
              const nextResult = normalizeStatsResult(payload.result!)
              setResult(nextResult)
              setActiveModuleKey(current => current || nextResult.modules[0]?.key || '')
            })
          }
        }
      })
    } catch (err) {
      setError('消息统计失败: ' + (err as Error).message)
    } finally {
      setLoading(false)
    }
  }, [jobId, loading])

  const activeModule = useMemo(() => {
    if (!result) return null
    const modules = result.modules || []
    return modules.find(module => module.key === activeModuleKey) || modules[0] || null
  }, [result, activeModuleKey])

  const finalTotal = useMemo(() => {
    return (result?.modules || []).reduce((sum, module) => sum + module.final_total, 0)
  }, [result])

  const modules = result?.modules || []

  const scopeLabel = '全量抓包'

  const handleDownloadExcel = useCallback(() => {
    if (!result) return

    const workbook = buildStatsWorkbookXLSX(result, scopeLabel)
    const workbookBuffer = workbook.buffer.slice(workbook.byteOffset, workbook.byteOffset + workbook.byteLength) as ArrayBuffer
    const blob = new Blob([workbookBuffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `message-stats-${formatTimestamp(new Date())}.xlsx`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
  }, [result, scopeLabel])

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 p-6 overflow-hidden">
      <div className={`flex flex-col gap-4 md:flex-row md:items-center md:justify-between ${collapsed ? '' : 'mb-5'}`}>
        <h3 className="text-lg font-bold text-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-500 to-cyan-600 flex items-center justify-center shadow-sm">
            <BarChart3 className="w-5 h-5 text-white" />
          </div>
          <span>消息统计</span>
          {collapsed && (
            <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-bold text-slate-500">
              {result ? `统计 ${finalTotal}` : scopeLabel}
            </span>
          )}
        </h3>

        <div className="flex items-center gap-2">
          <button
            onClick={handleLoadStats}
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all active:scale-[0.98]"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : result ? <RefreshCw className="w-4 h-4" /> : <Sigma className="w-4 h-4" />}
            <span>{loading ? '统计中...' : result ? '重新统计' : '开始统计'}</span>
          </button>

          <button
            onClick={handleDownloadExcel}
            disabled={loading || !result}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-300 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all active:scale-[0.98]"
          >
            <Download className="w-4 h-4" />
            <span>下载Excel</span>
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

      {collapsed && error && (
        <div className="mt-4 p-3 bg-red-50 rounded-lg text-red-700 text-sm font-medium">
          {error}
        </div>
      )}

      {!collapsed && (
        <>

      {loading && (
        <StreamProgressBar progress={progress} label="正在流式统计" unit="行" />
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <div className="bg-slate-50 rounded-lg px-4 py-3">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">统计范围</p>
          <p className="text-lg font-bold text-slate-800">{scopeLabel}</p>
        </div>
        <div className="bg-cyan-50 rounded-lg px-4 py-3">
          <p className="text-xs font-semibold text-cyan-700 uppercase tracking-wider mb-1">模块</p>
          <p className="text-lg font-bold text-cyan-900">{modules.length || 6}</p>
        </div>
        <div className="bg-emerald-50 rounded-lg px-4 py-3">
          <p className="text-xs font-semibold text-emerald-700 uppercase tracking-wider mb-1">统计结果</p>
          <p className="text-lg font-bold text-emerald-900">{finalTotal}</p>
        </div>
        <div className="bg-amber-50 rounded-lg px-4 py-3">
          <p className="text-xs font-semibold text-amber-700 uppercase tracking-wider mb-1">NAS修正</p>
          <p className="text-lg font-bold text-amber-900">
            {modules.flatMap(module => module.items || []).filter(item => item.correction !== 0).length || 0}
          </p>
        </div>
      </div>

      {error && (
        <div className="mb-5 p-3 bg-red-50 rounded-lg text-red-700 text-sm font-medium">
          {error}
        </div>
      )}

      {result?.truncated && (
        <div className="mb-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-800">
          抓包消息数量过大，已统计前 {formatCount(result.row_limit || 0)} 行匹配数据并停止继续读取，避免环境卡死。
        </div>
      )}

      {result && activeModule && (
        <div className="animate-fade-in">
          <div className="flex gap-2 overflow-x-auto pb-2 mb-4">
            {modules.map(module => {
              const active = module.key === activeModule.key
              return (
                <button
                  key={module.key}
                  onClick={() => setActiveModuleKey(module.key)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold whitespace-nowrap transition-colors ${
                    active
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-indigo-50 hover:text-indigo-700'
                  }`}
                >
                  <span>{module.name}</span>
                  <span className={`px-1.5 py-0.5 rounded-md text-xs ${active ? 'bg-white/20 text-white' : 'bg-white text-slate-500'}`}>
                    {module.final_total}
                  </span>
                </button>
              )
            })}
          </div>

          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="text-base font-bold text-slate-800">{activeModule.name}</p>
              {activeModule.standard && <p className="text-xs text-slate-500 mt-0.5">{activeModule.standard}</p>}
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500">合计</p>
              <p className="text-xl font-bold text-slate-900">{activeModule.final_total}</p>
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-slate-200">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold text-slate-600">消息名称</th>
                  <th className="px-4 py-3 text-left font-semibold text-slate-600">过滤条件</th>
                  <th className="px-4 py-3 text-right font-semibold text-slate-600">原始</th>
                  <th className="px-4 py-3 text-right font-semibold text-slate-600">修正</th>
                  <th className="px-4 py-3 text-right font-semibold text-slate-600">统计</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {(activeModule.items || []).map(item => (
                  <tr key={item.key} className="hover:bg-slate-50/80">
                    <td className="px-4 py-3 font-semibold text-slate-800 whitespace-nowrap">{item.name}</td>
                    <td className="px-4 py-3">
                      <code className="text-xs text-slate-600 bg-slate-50 px-2 py-1 rounded-md whitespace-nowrap">
                        {item.filter}
                      </code>
                    </td>
                    <td className="px-4 py-3 text-right text-slate-600 tabular-nums">{item.raw_count}</td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      {item.correction !== 0 ? (
                        <span title={item.correction_reason} className="font-semibold text-amber-700">
                          {item.correction}
                        </span>
                      ) : (
                        <span className="text-slate-300">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right font-bold text-slate-900 tabular-nums">{item.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

        </>
      )}
    </div>
  )
}

type XLSXCell = string | number | null

interface WorksheetSpec {
  name: string
  rows: XLSXCell[][]
  widths: number[]
}

function normalizeStatsResult(result: MessageStatsResult): MessageStatsResult {
  return {
    ...result,
    modules: (result.modules || []).map(module => ({
      ...module,
      items: module.items || [],
    })),
  }
}

function StreamProgressBar({ progress, label, unit }: { progress: StreamProgress | null; label: string; unit: string }) {
  const chunkRows = progress?.chunk_rows || 0
  const chunkTarget = progress?.chunk_target || 5000
  const percent = Math.min(100, Math.round((chunkRows / chunkTarget) * 100))
  return (
    <div className="mb-5 rounded-xl border border-cyan-100 bg-cyan-50 px-4 py-3">
      <div className="mb-2 flex items-center justify-between text-sm font-semibold text-cyan-800">
        <span>{label}</span>
        <span>第 {progress?.chunk_index || 1} 批 · 已处理 {formatCount(progress?.processed_rows || 0)} {unit}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-white">
        <div className="h-full rounded-full bg-cyan-600 transition-all duration-300" style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}

function buildStatsWorkbookXLSX(result: MessageStatsResult, scopeLabel: string): Uint8Array {
  const modules = result.modules || []
  const total = modules.reduce((sum, module) => sum + module.final_total, 0)
  const generatedAt = new Date().toLocaleString()

  const worksheets: WorksheetSpec[] = [
    {
      name: '汇总',
      widths: [18, 24, 18, 18, 18, 80],
      rows: [
        ['消息统计结果'],
        ['统计范围', scopeLabel, '统计时间', generatedAt],
        ['模块数', modules.length, '统计总数', total],
        ['过滤范围', result.scope_filter || '全量抓包'],
        [],
        ['模块', '标准', '原始合计', '统计合计', '修正项数'],
        ...modules.map(module => [
          module.name,
          module.standard || '',
          module.raw_total,
          module.final_total,
          (module.items || []).filter(item => item.correction !== 0).length,
        ]),
      ],
    },
    ...modules.map(module => ({
      name: module.name,
      widths: [42, 62, 12, 12, 12, 36],
      rows: [
        [module.name],
        ['标准', module.standard || '', '原始合计', module.raw_total, '统计合计', module.final_total],
        [],
        ['消息名称', '过滤条件', '原始', '修正', '统计', '修正原因'],
        ...(module.items || []).map(item => [
          item.name,
          item.filter,
          item.raw_count,
          item.correction === 0 ? null : item.correction,
          item.count,
          item.correction_reason || '',
        ]),
      ],
    })),
  ]

  return createXLSX(worksheets)
}

function createXLSX(worksheets: WorksheetSpec[]): Uint8Array {
  const usedNames = new Set<string>()
  const safeWorksheets = worksheets.map(sheet => ({
    ...sheet,
    name: uniqueSheetName(sheet.name, usedNames),
  }))

  const files: ZipFile[] = [
    textFile('[Content_Types].xml', contentTypesXML(safeWorksheets.length)),
    textFile('_rels/.rels', rootRelsXML()),
    textFile('docProps/app.xml', appXML()),
    textFile('docProps/core.xml', coreXML()),
    textFile('xl/workbook.xml', workbookXML(safeWorksheets)),
    textFile('xl/_rels/workbook.xml.rels', workbookRelsXML(safeWorksheets.length)),
    ...safeWorksheets.map((sheet, index) => textFile(`xl/worksheets/sheet${index + 1}.xml`, worksheetXML(sheet))),
  ]

  return zipStore(files)
}

function contentTypesXML(sheetCount: number): string {
  const worksheetOverrides = Array.from({ length: sheetCount }, (_, index) =>
    `<Override PartName="/xl/worksheets/sheet${index + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
  ).join('')

  return xmlHeader() + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
    <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
    <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
    ${worksheetOverrides}
  </Types>`
}

function rootRelsXML(): string {
  return xmlHeader() + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
    <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
  </Relationships>`
}

function appXML(): string {
  return xmlHeader() + `<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
    <Application>UE PCAP Filter</Application>
  </Properties>`
}

function coreXML(): string {
  const now = new Date().toISOString()
  return xmlHeader() + `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <dc:title>消息统计结果</dc:title>
    <dc:creator>UE PCAP Filter</dc:creator>
    <cp:lastModifiedBy>UE PCAP Filter</cp:lastModifiedBy>
    <dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created>
    <dcterms:modified xsi:type="dcterms:W3CDTF">${now}</dcterms:modified>
  </cp:coreProperties>`
}

function workbookXML(worksheets: WorksheetSpec[]): string {
  const sheets = worksheets.map((sheet, index) =>
    `<sheet name="${escapeXML(sheet.name)}" sheetId="${index + 1}" r:id="rId${index + 1}"/>`
  ).join('')

  return xmlHeader() + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <sheets>${sheets}</sheets>
  </workbook>`
}

function workbookRelsXML(sheetCount: number): string {
  const rels = Array.from({ length: sheetCount }, (_, index) =>
    `<Relationship Id="rId${index + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${index + 1}.xml"/>`
  ).join('')

  return xmlHeader() + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    ${rels}
  </Relationships>`
}

function worksheetXML(sheet: WorksheetSpec): string {
  const maxColumns = Math.max(sheet.widths.length, ...sheet.rows.map(row => row.length))
  const maxRows = Math.max(sheet.rows.length, 1)
  const cols = sheet.widths.map((width, index) =>
    `<col min="${index + 1}" max="${index + 1}" width="${width}" customWidth="1"/>`
  ).join('')
  const rows = sheet.rows.map((row, rowIndex) =>
    `<row r="${rowIndex + 1}">${row.map((cell, colIndex) => cellXML(cell, rowIndex + 1, colIndex + 1)).join('')}</row>`
  ).join('')

  return xmlHeader() + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <dimension ref="A1:${columnName(maxColumns)}${maxRows}"/>
    <cols>${cols}</cols>
    <sheetData>${rows}</sheetData>
  </worksheet>`
}

function cellXML(value: XLSXCell, row: number, col: number): string {
  const ref = `${columnName(col)}${row}`
  if (typeof value === 'number') {
    return `<c r="${ref}"><v>${value}</v></c>`
  }
  if (value === null || value === '') {
    return `<c r="${ref}"/>`
  }
  return `<c r="${ref}" t="inlineStr"><is><t>${escapeXML(value)}</t></is></c>`
}

function xmlHeader(): string {
  return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
}

function escapeXML(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function columnName(index: number): string {
  let name = ''
  let current = index
  while (current > 0) {
    current--
    name = String.fromCharCode(65 + (current % 26)) + name
    current = Math.floor(current / 26)
  }
  return name
}

function uniqueSheetName(name: string, usedNames: Set<string>): string {
  const clean = name.replace(/[\[\]:*?/\\]/g, ' ').trim() || 'Sheet'
  const base = clean.slice(0, 31)
  let candidate = base
  let index = 2
  while (usedNames.has(candidate)) {
    const suffix = ` ${index}`
    candidate = base.slice(0, 31 - suffix.length) + suffix
    index++
  }
  usedNames.add(candidate)
  return candidate
}

interface ZipFile {
  name: string
  data: Uint8Array
}

function textFile(name: string, content: string): ZipFile {
  return { name, data: new TextEncoder().encode(content) }
}

function zipStore(files: ZipFile[]): Uint8Array {
  const now = new Date()
  const dosTime = ((now.getHours() & 0x1f) << 11) | ((now.getMinutes() & 0x3f) << 5) | Math.floor(now.getSeconds() / 2)
  const dosDate = (((now.getFullYear() - 1980) & 0x7f) << 9) | (((now.getMonth() + 1) & 0x0f) << 5) | (now.getDate() & 0x1f)
  const localParts: Uint8Array[] = []
  const centralParts: Uint8Array[] = []
  let offset = 0

  for (const file of files) {
    const nameBytes = new TextEncoder().encode(file.name)
    const crc = crc32(file.data)
    const local = new Uint8Array(30 + nameBytes.length)
    const localView = new DataView(local.buffer)
    localView.setUint32(0, 0x04034b50, true)
    localView.setUint16(4, 20, true)
    localView.setUint16(6, 0x0800, true)
    localView.setUint16(8, 0, true)
    localView.setUint16(10, dosTime, true)
    localView.setUint16(12, dosDate, true)
    localView.setUint32(14, crc, true)
    localView.setUint32(18, file.data.length, true)
    localView.setUint32(22, file.data.length, true)
    localView.setUint16(26, nameBytes.length, true)
    localView.setUint16(28, 0, true)
    local.set(nameBytes, 30)
    localParts.push(local, file.data)

    const central = new Uint8Array(46 + nameBytes.length)
    const centralView = new DataView(central.buffer)
    centralView.setUint32(0, 0x02014b50, true)
    centralView.setUint16(4, 20, true)
    centralView.setUint16(6, 20, true)
    centralView.setUint16(8, 0x0800, true)
    centralView.setUint16(10, 0, true)
    centralView.setUint16(12, dosTime, true)
    centralView.setUint16(14, dosDate, true)
    centralView.setUint32(16, crc, true)
    centralView.setUint32(20, file.data.length, true)
    centralView.setUint32(24, file.data.length, true)
    centralView.setUint16(28, nameBytes.length, true)
    centralView.setUint16(30, 0, true)
    centralView.setUint16(32, 0, true)
    centralView.setUint16(34, 0, true)
    centralView.setUint16(36, 0, true)
    centralView.setUint32(38, 0, true)
    centralView.setUint32(42, offset, true)
    central.set(nameBytes, 46)
    centralParts.push(central)

    offset += local.length + file.data.length
  }

  const centralOffset = offset
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0)
  const end = new Uint8Array(22)
  const endView = new DataView(end.buffer)
  endView.setUint32(0, 0x06054b50, true)
  endView.setUint16(4, 0, true)
  endView.setUint16(6, 0, true)
  endView.setUint16(8, files.length, true)
  endView.setUint16(10, files.length, true)
  endView.setUint32(12, centralSize, true)
  endView.setUint32(16, centralOffset, true)
  endView.setUint16(20, 0, true)

  return concatUint8Arrays([...localParts, ...centralParts, end])
}

const crc32Table = Array.from({ length: 256 }, (_, index) => {
  let value = index
  for (let bit = 0; bit < 8; bit++) {
    value = (value & 1) !== 0 ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1)
  }
  return value >>> 0
})

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff
  for (const byte of data) {
    crc = crc32Table[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function concatUint8Arrays(parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((sum, part) => sum + part.length, 0)
  const output = new Uint8Array(size)
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

function formatTimestamp(date: Date): string {
  const pad = (value: number) => value.toString().padStart(2, '0')
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
    '-',
    pad(date.getHours()),
    pad(date.getMinutes()),
    pad(date.getSeconds()),
  ].join('')
}

function formatCount(value: number): string {
  return new Intl.NumberFormat('zh-CN').format(value)
}
