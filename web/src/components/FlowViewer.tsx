import { useState, useEffect, useRef, useCallback } from 'react'
import { ArrowLeft, Loader2, AlertCircle, Code, AlertTriangle, Search, FileText, Copy, Check } from 'lucide-react'
import { MermaidDiagram } from './MermaidDiagram'
import { DraggableWindow } from './DraggableWindow'
import { copyText } from '../utils/clipboard'
import { 
  deriveFlowDetails,
  deriveFlowDetailsFromTsharkColumns,
  type FlowDetailMapping, 
  type RichFlowDetail,
  type PacketColumns
} from '../utils/flowDetails'

// IPMapping maps an IP address to a network element role (from protocol-based inference)
interface IPMapping {
  ip: string
  ne: string  // gNB, AMF, SMF, UPF, etc.
  confidence?: number
  reason?: string
}

// FlowStageFrame represents a single frame within a stage
interface FlowStageFrame {
  number: string  // frame.number from input JSON
  title?: string  // message name for Mermaid label
  note?: string   // operation/effect description for Mermaid Note
}

// FlowStage represents a logical stage/phase in the signaling flow
interface FlowStage {
  name: string
  frames: FlowStageFrame[]  // explicit list of frames in this stage
  summary?: string
  confidence?: number
}

// FlowAnnotationsV1 is the structured JSON for IP-NE mapping annotations
interface FlowAnnotationsV1 {
  version: string
  flow_name?: string
  ip_map: IPMapping[]
  stages: FlowStage[]
}

interface FlowFinalPayload {
  flow_name: string
  mermaid: string
  details_map: FlowDetailMapping[]
  mode: 'full_fallback' | 'go_deterministic'
  reasons?: string[]
  stats?: {
    input_packets: number
    mermaid_messages: number
    mapping_entries: number
    removed_heartbeats: number
  }
  // Annotations (IP→NE mapping) inferred from protocols. May be null.
  annotations?: FlowAnnotationsV1 | null
  // PacketColumns from tshark (Protocol, Info, etc.) for each frame.
  // Used for message labels and packet details.
  packet_columns?: Record<string, PacketColumns> | null
}

// KeyParams from backend
interface KeyParams {
  imsi?: string[]
  ue_ip?: string[]
  teid?: string[]
  seid?: string[]
  qfi?: string[]
  ran_ue_ngap_id?: string[]
  amf_ue_ngap_id?: string[]
}

// FlowData combines parsed Mermaid output with derived details
interface FlowData {
  flow_name: string
  mermaid: string
  key_params?: KeyParams
  details: RichFlowDetail[]
  annotations?: FlowAnnotationsV1 | null
}

interface FlowViewerProps {
  jobId: string
  filter: string
  onBack: () => void
}

type StreamState = 'connecting' | 'streaming' | 'parsing' | 'completed' | 'error'

// Map display protocol names (from tshark columns) to tshark filter protocol names
function mapDisplayProtocolToFilter(displayProtocol: string): string {
  if (!displayProtocol) return ''
  
  let proto = displayProtocol.toLowerCase()
  
  // Handle compound protocols like "NGAP/NAS-5GS"
  if (proto.includes('/')) {
    proto = proto.split('/')[0]
  }
  
  // Remove any suffix like " (encrypted)"
  const spaceIdx = proto.indexOf(' ')
  if (spaceIdx > 0) {
    proto = proto.substring(0, spaceIdx)
  }
  
  // Map common display names to tshark filter names
  const mapping: Record<string, string> = {
    'ngap': 'ngap',
    's1ap': 's1ap',
    'pfcp': 'pfcp',
    'gtpv2': 'gtpv2',
    'gtp': 'gtp',
    'nas-5gs': 'nas-5gs',
    'nas-eps': 'nas-eps',
    'diameter': 'diameter',
    'sctp': 'sctp',
    'f1ap': 'f1ap',
    'e1ap': 'e1ap',
    'xnap': 'xnap',
    'x2ap': 'x2ap',
    // Additional aliases
    'gtp-u': 'gtp',
    'gtp-c': 'gtpv2',
    'gtpv2-c': 'gtpv2',
  }
  
  return mapping[proto] || proto
}

export function FlowViewer({ jobId, filter, onBack }: FlowViewerProps) {
  const [streamState, setStreamState] = useState<StreamState>('connecting')
  const [error, setError] = useState<string | null>(null)
  const [flowData, setFlowData] = useState<FlowData | null>(null)
  const [finalNote, setFinalNote] = useState<string | null>(null)
  // Message sequence number search
  const [searchIdx, setSearchIdx] = useState('')
  const [searchError, setSearchError] = useState<string | null>(null)
  // Active detail shown in modal (null = closed)
  const [activeDetail, setActiveDetail] = useState<RichFlowDetail | null>(null)
  // Protocol tree state for the active detail
  const [protocolTree, setProtocolTree] = useState<string | null>(null)
  const [protocolTreeLoading, setProtocolTreeLoading] = useState(false)
  const [protocolTreeError, setProtocolTreeError] = useState<string | null>(null)
  const [protocolTreeCopied, setProtocolTreeCopied] = useState(false)
  
  const streamContentRef = useRef('')
  const flowFinalRef = useRef<FlowFinalPayload | null>(null)
  
  // Store SSE data in refs to avoid useEffect dependency issues
  const keyParamsRef = useRef<KeyParams | null>(null)
  const inputJSONRef = useRef<string>('')
  const detailsMapRef = useRef<FlowDetailMapping[]>([])

  // Parse stream content to extract flow_name and mermaid code
  const parseStreamContent = useCallback((content: string) => {
    let flowName = '信令流程图'
    let mermaidCode = ''

    // Extract FLOW_NAME
    const flowNameMatch = content.match(/---FLOW_NAME---\s*([\s\S]*?)\s*---/)
    if (flowNameMatch) flowName = flowNameMatch[1].trim()

    // Extract MERMAID
    const mermaidMarker = '---MERMAID---'
    const detailsMarker = '---DETAILS---'
    const mermaidIdx = content.indexOf(mermaidMarker)
    const detailsIdx = content.indexOf(detailsMarker)

    if (mermaidIdx !== -1) {
      const start = mermaidIdx + mermaidMarker.length
      // Stop at DETAILS marker if present (backward compatibility), or any other --- marker
      let end = content.length
      if (detailsIdx !== -1 && detailsIdx > start) {
        end = detailsIdx
      } else {
        // Look for any other marker
        const nextMarker = content.indexOf('---', start + 1)
        if (nextMarker !== -1 && nextMarker > start) {
          end = nextMarker
        }
      }
      mermaidCode = content.slice(start, end).trim()
    } else {
      // Fallback: try to find mermaid code block
      const codeBlockMatch = content.match(/```mermaid\s*([\s\S]*?)```/)
      if (codeBlockMatch) {
        mermaidCode = codeBlockMatch[1].trim()
      } else {
        // Fallback: find sequenceDiagram directly
        const seqMatch = content.match(/(sequenceDiagram[\s\S]*)/)
        if (seqMatch) mermaidCode = seqMatch[1].trim()
      }
    }

    // Clean up trailing markdown
    if (mermaidCode.includes('```')) {
      mermaidCode = mermaidCode.substring(0, mermaidCode.lastIndexOf('```')).trim()
    }

    return { flowName, mermaidCode }
  }, [])

  // Handle SSE stream
  useEffect(() => {
    let cancelled = false
    const abortController = new AbortController()

    async function startStream() {
      try {
        setStreamState('connecting')
        setError(null)
        setFlowData(null)
        setFinalNote(null)
        flowFinalRef.current = null
        streamContentRef.current = ''
        keyParamsRef.current = null
        inputJSONRef.current = ''
        detailsMapRef.current = []

        const response = await fetch(`/api/jobs/${jobId}/flow/generate/stream`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filter, max_events: 200 }),
          signal: abortController.signal,
        })

        if (!response.ok) {
          const errorText = await response.text()
          throw new Error(`HTTP ${response.status}: ${errorText}`)
        }

        if (!response.body) {
          throw new Error('No response body')
        }

        setStreamState('streaming')

        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''
        let currentEvent = '' // Track current event across chunks

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          if (cancelled) break

          buffer += decoder.decode(value, { stream: true })

          // Process SSE events
          const lines = buffer.split('\n')
          buffer = lines.pop() || '' // Keep incomplete line in buffer

          for (const line of lines) {
            if (line.startsWith('event: ')) {
              currentEvent = line.substring(7).trim()
            } else if (line.startsWith('data: ')) {
              const data = line.substring(6)
              
              if (currentEvent === 'chunk') {
                try {
                  const chunk = JSON.parse(data) as string
                  streamContentRef.current += chunk
                } catch (e) {
                  console.error('Failed to parse chunk:', e)
                }
              } else if (currentEvent === 'key_params') {
                try {
                  const params = JSON.parse(data) as KeyParams
                  keyParamsRef.current = params
                } catch (e) {
                  console.error('Failed to parse key_params:', e)
                }
              } else if (currentEvent === 'input_json') {
                try {
                  // input_json is double-escaped JSON string
                  const inputJSON = JSON.parse(data) as string
                  inputJSONRef.current = inputJSON
                } catch (e) {
                  console.error('[FlowViewer] ❌ Failed to parse input_json:', e, 'data preview:', data.substring(0, 500))
                }
              } else if (currentEvent === 'details_map') {
                try {
                  const detailsMap = JSON.parse(data) as FlowDetailMapping[]
                  detailsMapRef.current = detailsMap
                } catch (e) {
                  console.error('Failed to parse details_map:', e)
                }
              } else if (currentEvent === 'flow_final') {
                try {
                  const payload = JSON.parse(data) as FlowFinalPayload
                  flowFinalRef.current = payload
                } catch (e) {
                  console.error('[FlowViewer] ❌ Failed to parse flow_final:', e)
                }
              } else if (currentEvent === 'error') {
                try {
                  const errorData = JSON.parse(data)
                  throw new Error(errorData.message || 'Unknown error')
                } catch (e) {
                  if (e instanceof SyntaxError) {
                    throw new Error(data)
                  }
                  throw e
                }
              } else if (currentEvent === 'done') {
                // Stream completed, parse content and derive details
                if (!cancelled) {
                  setStreamState('parsing')

                  // Prefer server-provided flow_final (guaranteed consistent with input_json)
                  const finalPayload = flowFinalRef.current
                  if (finalPayload && finalPayload.mermaid) {
                    // Derive flow details: prefer tshark columns when available (new method),
                    // fall back to deriveFlowDetails from input_json (legacy method)
                    let derived: RichFlowDetail[] = []
                    if (finalPayload.packet_columns && finalPayload.details_map?.length) {
                      // New: Use tshark-extracted columns for accurate Wireshark-style display
                      derived = deriveFlowDetailsFromTsharkColumns(
                        finalPayload.details_map,
                        finalPayload.packet_columns,
                        finalPayload.annotations
                      )
                    } else if (inputJSONRef.current && finalPayload.details_map?.length) {
                      // Fallback: derive from input_json (legacy method)
                      derived = deriveFlowDetails(inputJSONRef.current, finalPayload.details_map, finalPayload.annotations)
                    }

                    if (finalPayload.mode === 'full_fallback') {
                      setFinalNote(
                        `使用全量时序图展示。${finalPayload.reasons?.length ? `原因：${finalPayload.reasons.join('；')}` : ''}`
                      )
                    } else if (finalPayload.mode === 'go_deterministic') {
                      // Go always generates Mermaid, IP mapping from protocol rules
                      setFinalNote(null)
                    } else {
                      setFinalNote(null)
                    }

                    setFlowData({
                      flow_name: finalPayload.flow_name || '信令流程图',
                      mermaid: finalPayload.mermaid,
                      key_params: keyParamsRef.current || undefined,
                      details: derived,
                      annotations: finalPayload.annotations,
                    })
                    setStreamState('completed')
                    currentEvent = ''
                    continue
                  }

                  // Backward-compatible fallback: derive from streamed content + details_map
                  // Note: No annotations in fallback mode, so from/to uses port-based inference
                  const { flowName, mermaidCode } = parseStreamContent(streamContentRef.current)
                  const derived = inputJSONRef.current && detailsMapRef.current.length > 0
                    ? deriveFlowDetails(inputJSONRef.current, detailsMapRef.current, null)
                    : []
                  setFlowData({
                    flow_name: flowName,
                    mermaid: mermaidCode,
                    key_params: keyParamsRef.current || undefined,
                    details: derived,
                    annotations: undefined,
                  })
                  setStreamState('completed')
                }
              }
              currentEvent = ''
            }
          }
        }
      } catch (err) {
        if (!cancelled && (err as Error).name !== 'AbortError') {
          console.error('[FlowViewer] Stream error:', err)
          setError((err as Error).message || '流式传输失败')
          setStreamState('error')
        }
      }
    }

    startStream()

    return () => {
      cancelled = true
      abortController.abort()
    }
  }, [jobId, filter, parseStreamContent])

  // Fetch protocol tree when activeDetail changes
  useEffect(() => {
    if (!activeDetail) {
      // Reset tree state when modal closes
      setProtocolTree(null)
      setProtocolTreeError(null)
      setProtocolTreeLoading(false)
      return
    }

    // Map display protocol to tshark filter protocol
    const displayProtocol = activeDetail.protocol || ''
    const proto = mapDisplayProtocolToFilter(displayProtocol)
    const frameNumber = activeDetail.originNumber

    if (!proto || !frameNumber) {
      // Can't fetch tree without protocol or frame number
      setProtocolTree(null)
      setProtocolTreeError(null)
      return
    }

    let cancelled = false
    async function fetchTree() {
      setProtocolTreeLoading(true)
      setProtocolTreeError(null)
      setProtocolTree(null)

      try {
        const resp = await fetch(`/api/jobs/${jobId}/packets/${frameNumber}/tree?proto=${encodeURIComponent(proto)}`)
        if (cancelled) return

        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }))
          throw new Error(errData.error || `HTTP ${resp.status}`)
        }

        const data = await resp.json()
        if (cancelled) return

        if (data.success && data.data?.tree) {
          setProtocolTree(data.data.tree)
        } else {
          throw new Error(data.error || '返回数据格式错误')
        }
      } catch (err) {
        if (!cancelled) {
          setProtocolTreeError((err as Error).message)
        }
      } finally {
        if (!cancelled) {
          setProtocolTreeLoading(false)
        }
      }
    }

    fetchTree()

    return () => {
      cancelled = true
    }
  }, [activeDetail, jobId])

  // Open detail modal by idx (only opens modal, no diagram state change)
  const openDetailByIdx = useCallback(
    (idx: number) => {
      if (!flowData?.details) return
      const detail = flowData.details.find((d) => d.idx === idx)
      if (detail) {
        setActiveDetail(detail)
      }
    },
    [flowData?.details]
  )

  // Handle search submit - only opens modal, does not change diagram state
  const handleSearch = useCallback(() => {
    const trimmed = searchIdx.trim()
    if (!trimmed) {
      setSearchError('请输入消息序号')
      return
    }
    const parsed = parseInt(trimmed, 10)
    if (isNaN(parsed) || parsed <= 0) {
      setSearchError('请输入有效的消息序号')
      return
    }
    if (!flowData?.details) return
    const detail = flowData.details.find((d) => d.idx === parsed)
    if (detail) {
      setActiveDetail(detail)
      setSearchError(null)
    } else {
      setSearchError(`未找到序号 ${parsed} 的消息`)
    }
  }, [searchIdx, flowData?.details])

  // Render loading/connecting state
  if (streamState === 'connecting') {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 bg-gradient-to-br from-violet-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg animate-pulse">
            <Loader2 className="w-8 h-8 text-white animate-spin" />
          </div>
          <h3 className="text-lg font-semibold text-slate-700 mb-2">正在分析</h3>
          <p className="text-sm text-slate-500">准备生成信令流程图...</p>
        </div>
      </div>
    )
  }

  // Render error state
  if (streamState === 'error') {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="text-center max-w-md">
          <div className="w-16 h-16 bg-red-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <AlertCircle className="w-8 h-8 text-red-500" />
          </div>
          <h3 className="text-lg font-semibold text-slate-700 mb-2">生成失败</h3>
          <p className="text-sm text-red-500 mb-4">{error}</p>
          <button
            onClick={onBack}
            className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-colors"
          >
            返回
          </button>
        </div>
      </div>
    )
  }

  // Render streaming output and final chart
  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-40">
        <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="flex items-center gap-2 px-3 py-2 text-slate-600 hover:text-violet-600 hover:bg-violet-50 rounded-xl transition-all"
            >
              <ArrowLeft className="w-5 h-5" />
              <span className="font-medium">返回</span>
            </button>
            <div className="h-8 w-px bg-slate-200" />
            <div className="flex items-center gap-2">
              {streamState === 'streaming' && (
                <div className="flex items-center gap-2 text-violet-600">
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span className="font-medium">正在生成...</span>
                </div>
              )}
              {streamState === 'parsing' && (
                <div className="flex items-center gap-2 text-amber-600">
                  <Code className="w-5 h-5 animate-pulse" />
                  <span className="font-medium">正在解析图表...</span>
                </div>
              )}
              {streamState === 'completed' && flowData && (
                <h1 className="text-lg font-bold text-slate-900">{flowData.flow_name}</h1>
              )}
            </div>
          </div>

          {/* Search box - only show when completed */}
          {streamState === 'completed' && flowData && (
            <div className="flex items-center gap-2">
              <div className="relative">
                <input
                  type="text"
                  inputMode="numeric"
                  value={searchIdx}
                  onChange={(e) => {
                    // Only allow digits
                    const val = e.target.value.replace(/\D/g, '')
                    setSearchIdx(val)
                    setSearchError(null)
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleSearch()
                  }}
                  placeholder="消息序号"
                  className={`w-28 px-3 py-1.5 text-sm rounded-lg border ${
                    searchError
                      ? 'border-red-300 focus:ring-red-300'
                      : 'border-slate-200 focus:ring-violet-300'
                  } focus:outline-none focus:ring-2 transition-colors`}
                />
                {searchError && (
                  <div className="absolute top-full left-0 mt-1 px-2 py-1 bg-red-50 border border-red-200 rounded text-xs text-red-600 whitespace-nowrap z-50">
                    {searchError}
                  </div>
                )}
              </div>
              <button
                onClick={handleSearch}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-violet-500 hover:bg-violet-600 text-white text-sm font-medium rounded-lg transition-colors"
              >
                <Search className="w-4 h-4" />
                <span>查询</span>
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 p-4 sm:p-6 lg:p-8">
        {/* Loading indicator during streaming and parsing */}
        {(streamState === 'streaming' || streamState === 'parsing') && (
          <div className="mb-6 flex items-center justify-center py-8">
            <div className="flex items-center gap-3 text-violet-600">
              <Loader2 className="w-6 h-6 animate-spin" />
              <span className="font-medium">
                {streamState === 'streaming' ? '正在生成流程图...' : '正在解析图表...'}
              </span>
            </div>
          </div>
        )}

        {/* Mermaid diagram - shown after completion */}
        {streamState === 'completed' && flowData && flowData.mermaid && (
          <div className="animate-fade-in">
            {finalNote && (
              <div className="mb-4 rounded-xl border border-amber-200 bg-amber-50 p-4 text-amber-900 flex items-start gap-3">
                <div className="mt-0.5 flex-shrink-0">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div className="text-sm">{finalNote}</div>
              </div>
            )}
            <MermaidDiagram
              code={flowData.mermaid}
              className="w-full"
              onMessageClick={(idx) => {
                openDetailByIdx(idx)
              }}
              onActorClick={() => {}}
            />
          </div>
        )}

        {/* Draggable detail window */}
        {activeDetail && (
          <DraggableWindow
            title={`#${activeDetail.idx} ${activeDetail.title}`}
            subtitle={
              [
                activeDetail.from && activeDetail.to ? `${activeDetail.from} → ${activeDetail.to}` : '',
                activeDetail.originNumber ? `frame=${activeDetail.originNumber}` : '',
                activeDetail.protocol || '',
              ]
                .filter(Boolean)
                .join(' · ')
            }
            onClose={() => setActiveDetail(null)}
            minWidth={520}
            minHeight={400}
          >
            <div className="space-y-4 text-sm text-slate-700">
              {/* Protocol Tree Section - Primary display */}
              <div className="border border-slate-200 rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-3 py-2 bg-gradient-to-r from-violet-50 to-purple-50 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-violet-600" />
                    <span className="font-medium text-violet-800">协议树 (Wireshark 展开)</span>
                  </div>
                  {protocolTree && (
                    <button
                      onClick={async () => {
                        const copied = await copyText(protocolTree)
                        if (!copied) return
                        setProtocolTreeCopied(true)
                        setTimeout(() => setProtocolTreeCopied(false), 2000)
                      }}
                      className="flex items-center gap-1 px-2 py-1 text-xs text-slate-600 hover:text-violet-600 hover:bg-violet-100 rounded transition-colors"
                    >
                      {protocolTreeCopied ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-green-600" />
                          <span className="text-green-600">已复制</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>复制</span>
                        </>
                      )}
                    </button>
                  )}
                </div>
                <div className="p-3 bg-slate-900 max-h-72 overflow-auto">
                  {protocolTreeLoading && (
                    <div className="flex items-center gap-2 text-slate-400">
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>加载协议树...</span>
                    </div>
                  )}
                  {protocolTreeError && (
                    <div className="flex items-center gap-2 text-amber-400">
                      <AlertCircle className="w-4 h-4" />
                      <span>{protocolTreeError}</span>
                    </div>
                  )}
                  {protocolTree && (
                    <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap break-words leading-relaxed"
                      style={{ textShadow: '0 0 8px rgba(74, 222, 128, 0.2)' }}>
                      {protocolTree}
                    </pre>
                  )}
                  {!protocolTreeLoading && !protocolTreeError && !protocolTree && (
                    <div className="text-slate-500 text-xs">
                      无法获取协议树（协议不支持或帧号无效）
                    </div>
                  )}
                </div>
              </div>

              {/* Detail Lines Section - Secondary */}
              {activeDetail.detail_lines.length > 0 && (
                <details className="group">
                  <summary className="cursor-pointer text-slate-600 hover:text-violet-600 font-medium flex items-center gap-1">
                    <span className="text-xs">▶</span>
                    <span>详情行 ({activeDetail.detail_lines.length})</span>
                  </summary>
                  <div className="mt-2 space-y-1 pl-4 border-l-2 border-slate-200">
                    {activeDetail.detail_lines.map((line, i) => (
                      <div key={i} className="break-words font-mono text-xs text-slate-600">
                        {line}
                      </div>
                    ))}
                  </div>
                </details>
              )}

              {/* Raw Fields Section - Tertiary */}
              {Object.keys(activeDetail.fields).length > 0 && (
                <details className="group">
                  <summary className="cursor-pointer text-slate-600 hover:text-violet-600 font-medium flex items-center gap-1">
                    <span className="text-xs">▶</span>
                    <span>原始字段</span>
                  </summary>
                  <pre className="mt-2 p-3 bg-slate-50 rounded-lg border border-slate-200 overflow-x-auto whitespace-pre-wrap break-words text-[11px] font-mono">
                    {JSON.stringify(activeDetail.fields, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          </DraggableWindow>
        )}
      </main>
    </div>
  )
}
