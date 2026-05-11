import { useEffect, useRef, useState, useId, useCallback } from 'react'
import mermaid from 'mermaid'
import { AlertCircle, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react'
import { copyText } from '../utils/clipboard'

// Initialize mermaid with balanced settings for sequence diagrams - readable overview
mermaid.initialize({
  startOnLoad: false,
  // 使用 'loose' 以支持 <br/> 等 HTML 标签在消息中渲染
  securityLevel: 'loose',
  theme: 'default',
  sequence: {
    diagramMarginX: 40,
    diagramMarginY: 20,
    // 适中的 actor 间距
    actorMargin: 280,
    // 适中的 actor 尺寸
    width: 140,
    height: 50,
    boxMargin: 10,
    boxTextMargin: 6,
    noteMargin: 12,
    // 适中的消息间距
    messageMargin: 40,
    mirrorActors: true,
    // 禁用 useMaxWidth，让图表可以水平滚动
    useMaxWidth: false,
    rightAngles: false,
    showSequenceNumbers: true,
    // 消息文本包裹
    wrapPadding: 15,
    wrap: true,
    // 适中的字号
    messageFontSize: 11,
    // Note 相关设置
    noteFontSize: 9,
    // 消息文本居中
    messageAlign: 'center',
  },
  // 全局字体设置
  fontFamily: 'ui-sans-serif, system-ui, sans-serif',
  fontSize: 11,
})

interface MermaidDiagramProps {
  code: string
  className?: string
  highlightMessageIndex?: number // 1-based index (matches Mermaid autonumber order)
  onMessageClick?: (messageIndex: number) => void // 1-based index
  onActorClick?: (actorName: string) => void
}

export function MermaidDiagram({
  code,
  className = '',
  highlightMessageIndex,
  onMessageClick,
  onActorClick,
}: MermaidDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [error, setError] = useState<string | null>(null)
  const [showSource, setShowSource] = useState(false)
  const [copied, setCopied] = useState(false)
  const [svgReady, setSvgReady] = useState(false)
  const uniqueId = useId().replace(/:/g, '_')

  /**
   * Apply highlight to a specific message using sequence numbers for reliable matching.
   * Uses Y-coordinate matching between sequence numbers and message elements
   * to correctly identify which message text/line belongs to which sequence number.
   */
  const applyHighlight = useCallback(() => {
    const container = containerRef.current
    if (!container) return
    const svg = container.querySelector('svg')
    if (!svg) return

    const textEls = Array.from(svg.querySelectorAll<SVGTextElement>('text.messageText'))
    const lineEls = Array.from(svg.querySelectorAll<SVGPathElement>('path.messageLine0, path.messageLine1'))
    const seqNumEls = Array.from(svg.querySelectorAll<SVGTextElement>('text.sequenceNumber'))

    // Reset classes
    for (const el of [...textEls, ...lineEls]) {
      el.classList.remove('uepcap-highlight')
      el.classList.remove('uepcap-dim')
    }

    if (!highlightMessageIndex || highlightMessageIndex <= 0) return

    // Build a map of sequence number -> Y coordinate
    const seqNumYMap = new Map<number, number>()
    for (const el of seqNumEls) {
      const num = parseInt(el.textContent?.trim() || '', 10)
      if (!isNaN(num) && num > 0) {
        const rect = el.getBoundingClientRect()
        seqNumYMap.set(num, rect.top + rect.height / 2)
      }
    }

    const targetY = seqNumYMap.get(highlightMessageIndex)
    if (targetY === undefined) {
      // Fallback to index-based if sequence number not found
      const target = highlightMessageIndex - 1
      textEls.forEach((el, i) => el.classList.add(i === target ? 'uepcap-highlight' : 'uepcap-dim'))
      lineEls.forEach((el, i) => el.classList.add(i === target ? 'uepcap-highlight' : 'uepcap-dim'))
      return
    }

    // Highlight elements by matching Y-coordinate
    const Y_THRESHOLD = 30
    
    for (const el of textEls) {
      const rect = el.getBoundingClientRect()
      const elY = rect.top + rect.height / 2
      const dist = Math.abs(elY - targetY)
      
      if (dist < Y_THRESHOLD) {
        el.classList.add('uepcap-highlight')
      } else {
        el.classList.add('uepcap-dim')
      }
    }

    for (const el of lineEls) {
      const rect = el.getBoundingClientRect()
      const elY = rect.top + rect.height / 2
      const dist = Math.abs(elY - targetY)
      
      if (dist < Y_THRESHOLD) {
        el.classList.add('uepcap-highlight')
      } else {
        el.classList.add('uepcap-dim')
      }
    }
  }, [highlightMessageIndex])

  /**
   * Resolve message index from a clicked element using Mermaid's rendered sequence numbers.
   * This is more reliable than DOM order because Mermaid's autonumber sequence numbers
   * are explicitly rendered and their text content directly indicates the message index.
   * 
   * Strategy:
   * 1. If user clicks on a sequenceNumber element, parse its text content directly
   * 2. For message text/line clicks, find the nearest sequence number by Y-coordinate
   * 3. Fall back to legacy DOM-order logic if the new approach fails
   */
  const resolveMessageIndexFromTarget = useCallback((targetEl: Element) => {
    const container = containerRef.current
    if (!container) return null
    const svg = container.querySelector('svg')
    if (!svg) return null

    // Get all sequence number text elements (Mermaid renders these with autonumber)
    const seqNumEls = Array.from(svg.querySelectorAll<SVGTextElement>('text.sequenceNumber'))
    
    // === Priority 1: Direct click on sequence number ===
    const seqNumEl = targetEl.closest('text.sequenceNumber')
    if (seqNumEl && seqNumEl.textContent) {
      const parsed = parseInt(seqNumEl.textContent.trim(), 10)
      if (!isNaN(parsed) && parsed > 0) {
        return parsed
      }
    }
    
    // Also check if clicking on the rect background of a sequence number
    const seqNumRect = targetEl.closest('rect.sequenceNumber')
    if (seqNumRect) {
      // Find the sibling text element in the same group
      const parentG = seqNumRect.closest('g')
      if (parentG) {
        const siblingText = parentG.querySelector('text.sequenceNumber')
        if (siblingText?.textContent) {
          const parsed = parseInt(siblingText.textContent.trim(), 10)
          if (!isNaN(parsed) && parsed > 0) {
            return parsed
          }
        }
      }
    }

    // === Priority 2: Message text or line click - find nearest sequence number by Y-coordinate ===
    const isMessageClick = 
      targetEl.closest('text.messageText') || 
      targetEl.closest('path.messageLine0, path.messageLine1') ||
      targetEl.closest('tspan')?.closest('text.messageText')
    
    if (isMessageClick && seqNumEls.length > 0) {
      // Get Y-coordinate of clicked element (use center)
      const targetRect = targetEl.getBoundingClientRect()
      const targetY = targetRect.top + targetRect.height / 2

      // Find the sequence number closest in Y-coordinate
      let closestEl: SVGTextElement | null = null
      let closestDist = Infinity

      for (const el of seqNumEls) {
        const rect = el.getBoundingClientRect()
        const elY = rect.top + rect.height / 2
        const dist = Math.abs(elY - targetY)
        
        if (dist < closestDist) {
          closestDist = dist
          closestEl = el
        }
      }

      // Use a reasonable threshold to prevent mismatches
      const Y_THRESHOLD = 30
      if (closestEl && closestDist < Y_THRESHOLD && closestEl.textContent) {
        const parsed = parseInt(closestEl.textContent.trim(), 10)
        if (!isNaN(parsed) && parsed > 0) {
          return parsed
        }
      }
    }

    // === Fallback: Legacy DOM-order based resolution (kept for edge cases) ===
    const textEls = Array.from(svg.querySelectorAll<SVGTextElement>('text.messageText'))
    if (!textEls.length) return null

    const messageTextEl = targetEl.closest('text.messageText')
    if (messageTextEl) {
      const idx = textEls.indexOf(messageTextEl as SVGTextElement)
      if (idx >= 0) {
        return idx + 1
      }
    }

    const lineEl = targetEl.closest('path.messageLine0, path.messageLine1')
    if (lineEl) {
      // Best-effort: try to find a messageText in the same group
      const g = (lineEl as Element).closest('g')
      if (g) {
        const siblingText = g.querySelector('text.messageText')
        if (siblingText) {
          const idx = textEls.indexOf(siblingText as SVGTextElement)
          if (idx >= 0) {
            return idx + 1
          }
        }
      }

      // Fallback: if line count matches text count, map by order
      const lineEls = Array.from(svg.querySelectorAll<SVGPathElement>('path.messageLine0, path.messageLine1'))
      if (lineEls.length === textEls.length) {
        const idx = lineEls.indexOf(lineEl as SVGPathElement)
        if (idx >= 0) {
          return idx + 1
        }
      }
    }

    return null
  }, [])

  const resolveActorNameFromTarget = useCallback((targetEl: Element) => {
    const actorText = targetEl.closest('text.actor')
    if (actorText?.textContent?.trim()) return actorText.textContent.trim()

    // Sometimes the clickable area is rect/g; attempt to locate actor text nearby
    const g = targetEl.closest('g.actor')
    const txt = g?.querySelector('text.actor')
    if (txt?.textContent?.trim()) return txt.textContent.trim()

    return null
  }, [])

  /**
   * Adjust message text alignment based on arrow direction.
   * - All messages: text positioned ABOVE the arrow line
   * - Request (arrow pointing right): text aligned to left
   * - Response (arrow pointing left): text aligned to right
   * 
   * NOTE: Currently disabled due to Mermaid version compatibility issues.
   * The function is kept for future use when the correct selector is found.
   */
  // @ts-ignore - Temporarily disabled, kept for future use
  const _adjustMessageAlignment = useCallback((container: HTMLDivElement) => {
    const svg = container.querySelector('svg')
    if (!svg) return

    // Try multiple selectors for message lines (Mermaid version compatibility)
    // Old versions: path.messageLine0, path.messageLine1
    // New versions: line.messageLine0, line.messageLine1 or line elements in message groups
    let messageLines = Array.from(svg.querySelectorAll<SVGLineElement | SVGPathElement>(
      'path.messageLine0, path.messageLine1, line.messageLine0, line.messageLine1'
    ))
    
    // Fallback: find line elements that are part of message arrows
    if (messageLines.length === 0) {
      // Try finding lines within message-related groups
      messageLines = Array.from(svg.querySelectorAll<SVGLineElement>('line'))
    }
    
    const messageTexts = Array.from(svg.querySelectorAll<SVGTextElement>('text.messageText'))

    // If no lines found, stop; Mermaid versions differ in rendered SVG structure.
    if (messageLines.length === 0) {
      return
    }

    // Build a map of Y-coordinate to message line for matching
    const linesByY = new Map<number, SVGLineElement | SVGPathElement>()
    for (const line of messageLines) {
      try {
        // For <line> elements, use y1/y2 attributes; for <path>, use getBBox
        let centerY: number
        if (line.tagName.toLowerCase() === 'line') {
          const y1 = parseFloat(line.getAttribute('y1') || '0')
          const y2 = parseFloat(line.getAttribute('y2') || '0')
          centerY = (y1 + y2) / 2
        } else {
          const bbox = line.getBBox()
          centerY = bbox.y + bbox.height / 2
        }
        linesByY.set(Math.round(centerY), line)
      } catch (e) {
        // getBBox can fail for hidden elements
      }
    }

    for (const textEl of messageTexts) {
      const textBbox = textEl.getBBox()
      const textCenterY = Math.round(textBbox.y + textBbox.height / 2)
      
      // Find the closest line by Y-coordinate
      let closestLine: SVGLineElement | SVGPathElement | null = null
      let closestDist = Infinity
      
      for (const [y, line] of linesByY) {
        const dist = Math.abs(y - textCenterY)
        if (dist < closestDist && dist < 80) { // Threshold for matching
          closestDist = dist
          closestLine = line
        }
      }
      
      if (!closestLine) continue
      
      // Determine arrow direction
      let startX: number, endX: number
      
      if (closestLine.tagName.toLowerCase() === 'line') {
        // For <line> elements, use x1/x2 attributes
        startX = parseFloat(closestLine.getAttribute('x1') || '0')
        endX = parseFloat(closestLine.getAttribute('x2') || '0')
      } else {
        // For <path> elements, parse the 'd' attribute
        const pathD = closestLine.getAttribute('d')
        if (!pathD) continue
        
        const coords = pathD.match(/[\d.-]+/g)
        if (!coords || coords.length < 4) continue
        
        startX = parseFloat(coords[0])
        endX = parseFloat(coords[coords.length - 2])
      }
      
      // Get line bounding box for positioning
      let lineBbox: DOMRect | { x: number; y: number; width: number; height: number }
      if (closestLine.tagName.toLowerCase() === 'line') {
        const x1 = parseFloat(closestLine.getAttribute('x1') || '0')
        const x2 = parseFloat(closestLine.getAttribute('x2') || '0')
        const y1 = parseFloat(closestLine.getAttribute('y1') || '0')
        const y2 = parseFloat(closestLine.getAttribute('y2') || '0')
        lineBbox = {
          x: Math.min(x1, x2),
          y: Math.min(y1, y2),
          width: Math.abs(x2 - x1),
          height: Math.abs(y2 - y1)
        }
      } else {
        lineBbox = closestLine.getBBox()
      }
      
      // Calculate position above the line (8px above the line)
      const textY = lineBbox.y - 8
      textEl.setAttribute('y', String(textY))
      
      // If end X is less than start X, arrow points left (response)
      const isLeftArrow = endX < startX
      
      if (isLeftArrow) {
        // Response message (arrow pointing left): align text to right
        textEl.setAttribute('text-anchor', 'end')
        const rightEdge = lineBbox.x + lineBbox.width - 25
        textEl.setAttribute('x', String(rightEdge))
      } else {
        // Request message (arrow pointing right): align text to left
        textEl.setAttribute('text-anchor', 'start')
        const leftEdge = lineBbox.x + 25
        textEl.setAttribute('x', String(leftEdge))
      }
    }
  }, [])

  // Preprocess Mermaid code to wrap long Note text with <br/> tags
  const preprocessCode = useCallback((rawCode: string): string => {
    const MAX_LINE_LENGTH = 50 // Max characters per line in notes
    
    // Match Note lines: Note over/left of/right of Actor: text
    // or multi-line Note blocks
    return rawCode.replace(
      /(Note\s+(?:over|left of|right of)\s+[^:]+:\s*)(.+)$/gm,
      (match, prefix, noteText) => {
        // Skip if already has <br/> or is short enough
        if (noteText.includes('<br') || noteText.length <= MAX_LINE_LENGTH) {
          return match
        }
        
        // Split long text into lines
        const words = noteText.split(/(\s+)/)
        const lines: string[] = []
        let currentLine = ''
        
        for (const word of words) {
          if ((currentLine + word).length > MAX_LINE_LENGTH && currentLine.trim()) {
            lines.push(currentLine.trim())
            currentLine = word.trimStart()
          } else {
            currentLine += word
          }
        }
        if (currentLine.trim()) {
          lines.push(currentLine.trim())
        }
        
        return prefix + lines.join('<br/>')
      }
    )
  }, [])

  useEffect(() => {
    if (!containerRef.current || !code.trim()) return

    let cancelled = false
    setSvgReady(false)

    async function renderDiagram() {
      try {
        setError(null)
        
        // Clear previous content
        if (containerRef.current) {
          containerRef.current.innerHTML = ''
        }

        // Generate unique ID for this render
        const diagramId = `mermaid-${uniqueId}-${Date.now()}`
        
        // Preprocess code to wrap long notes
        const processedCode = preprocessCode(code)
        
        // Render the diagram
        const { svg } = await mermaid.render(diagramId, processedCode)
        
        if (!cancelled && containerRef.current) {
          containerRef.current.innerHTML = svg
          
          // NOTE: adjustMessageAlignment is disabled because new Mermaid versions
          // use different SVG structure. The default Mermaid alignment is used instead.
          // TODO: Re-enable after fixing the line element selector
          // adjustMessageAlignment(containerRef.current)
          
          // Apply highlight after render (if any)
          applyHighlight()
          // Signal that SVG is ready for click handling
          setSvgReady(true)
        }
      } catch (err) {
        if (!cancelled) {
          console.error('[MermaidDiagram] Render error:', err)
          setError((err as Error).message || '渲染 Mermaid 图表失败')
        }
      }
    }

    renderDiagram()

    return () => {
      cancelled = true
    }
  }, [code, uniqueId, applyHighlight, preprocessCode])

  // Click handling (event delegation on rendered SVG)
  // Depends on svgReady to ensure handler is attached after async render completes
  useEffect(() => {
    if (!svgReady) return
    const container = containerRef.current
    if (!container) return
    const svg = container.querySelector('svg')
    if (!svg) return

    const handler = (e: MouseEvent) => {
      const t = e.target
      if (!(t instanceof Element)) return

      const messageIdx = resolveMessageIndexFromTarget(t)
      if (messageIdx) {
        if (onMessageClick) {
          onMessageClick(messageIdx)
        }
        return
      }

      const actorName = resolveActorNameFromTarget(t)
      if (actorName) {
        if (onActorClick) {
          onActorClick(actorName)
        }
        return
      }

    }

    svg.addEventListener('click', handler)
    return () => {
      svg.removeEventListener('click', handler)
    }
  }, [svgReady, onActorClick, onMessageClick, resolveActorNameFromTarget, resolveMessageIndexFromTarget])

  // Update highlight without re-rendering the diagram
  useEffect(() => {
    applyHighlight()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightMessageIndex])

  const handleCopy = async () => {
    try {
      const copied = await copyText(code)
      if (!copied) return
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  if (error) {
    return (
      <div className={`bg-red-50 rounded-xl border border-red-200 overflow-hidden ${className}`}>
        {/* Error header */}
        <div className="p-4 flex items-start gap-3">
          <div className="w-10 h-10 bg-red-100 rounded-xl flex items-center justify-center flex-shrink-0">
            <AlertCircle className="w-5 h-5 text-red-500" />
          </div>
          <div className="flex-1 min-w-0">
            <h4 className="font-semibold text-red-700 mb-1">Mermaid 渲染失败</h4>
            <p className="text-sm text-red-600 break-words">{error}</p>
          </div>
        </div>

        {/* Show source toggle */}
        <div className="border-t border-red-200">
          <button
            onClick={() => setShowSource(!showSource)}
            className="w-full px-4 py-2 flex items-center justify-between text-sm text-red-600 hover:bg-red-100 transition-colors"
          >
            <span>查看源码</span>
            {showSource ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </button>
          
          {showSource && (
            <div className="relative">
              <button
                onClick={handleCopy}
                className="absolute top-2 right-2 p-2 bg-white/80 hover:bg-white rounded-lg text-red-600 transition-colors"
                title="复制源码"
              >
                {copied ? (
                  <Check className="w-4 h-4" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
              <pre className="p-4 bg-red-100/50 text-xs text-red-800 overflow-x-auto max-h-64 overflow-y-auto font-mono whitespace-pre-wrap break-all">
                {code}
              </pre>
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className={`relative ${className}`}>
      {/* Diagram container - balanced for readable overview */}
      <div
        ref={containerRef}
        className="mermaid-container overflow-x-auto overflow-y-auto bg-white rounded-xl border border-slate-200 p-3"
        style={{ 
          minHeight: 550,
          maxHeight: '570vh',
        }}
      />
      
      {/* CSS for mermaid message text - balanced for readable overview */}
      <style>{`
        .mermaid-container .messageText {
          font-size: 11px !important;
          fill: #1f2937 !important;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
        }
        .mermaid-container .messageText tspan {
          font-size: 11px !important;
          fill: #1f2937 !important;
        }
        .mermaid-container text.messageText {
          dominant-baseline: middle !important;
          text-anchor: start !important;
        }
        .mermaid-container .actor {
          font-size: 11px !important;
          font-weight: 600 !important;
        }
        .mermaid-container .actor-box {
          fill: #f8fafc !important;
          stroke: #94a3b8 !important;
        }
        .mermaid-container .note {
          font-size: 9px !important;
          fill: #fef3c7 !important;
        }
        .mermaid-container .noteText {
          font-size: 9px !important;
          fill: #92400e !important;
        }
        .mermaid-container .labelText {
          font-size: 9px !important;
        }
        .mermaid-container svg {
          max-width: none !important;
        }
        .mermaid-container .messageLine0,
        .mermaid-container .messageLine1 {
          stroke: #6366f1 !important;
          stroke-width: 1.2px !important;
        }
        .mermaid-container text.messageText,
        .mermaid-container .messageLine0,
        .mermaid-container .messageLine1,
        .mermaid-container text.actor,
        .mermaid-container .actor-box,
        .mermaid-container text.sequenceNumber,
        .mermaid-container rect.sequenceNumber {
          cursor: pointer;
        }
        .mermaid-container .arrowhead {
          fill: #6366f1 !important;
        }
        .mermaid-container .sequenceNumber {
          fill: white !important;
          font-size: 9px !important;
          font-weight: 600 !important;
        }
        .mermaid-container rect.sequenceNumber {
          fill: #6366f1 !important;
        }
        .mermaid-container .uepcap-highlight {
          opacity: 1 !important;
          filter: drop-shadow(0 0 5px rgba(99, 102, 241, 0.35));
        }
        .mermaid-container .uepcap-dim {
          opacity: 0.25 !important;
        }
      `}</style>
      
      {/* Copy source button (on success) */}
      <div className="absolute top-2 right-2 flex gap-2">
        <button
          onClick={() => setShowSource(!showSource)}
          className="p-2 bg-white/90 hover:bg-white rounded-lg text-slate-500 hover:text-slate-700 transition-colors shadow-sm border border-slate-200"
          title={showSource ? '隐藏源码' : '查看源码'}
        >
          {showSource ? (
            <ChevronUp className="w-4 h-4" />
          ) : (
            <ChevronDown className="w-4 h-4" />
          )}
        </button>
        <button
          onClick={handleCopy}
          className="p-2 bg-white/90 hover:bg-white rounded-lg text-slate-500 hover:text-slate-700 transition-colors shadow-sm border border-slate-200"
          title="复制源码"
        >
          {copied ? (
            <Check className="w-4 h-4 text-green-500" />
          ) : (
            <Copy className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Source code panel */}
      {showSource && (
        <div className="mt-3 bg-slate-50 rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-4 py-2 bg-slate-100 border-b border-slate-200 flex items-center justify-between">
            <span className="text-xs font-medium text-slate-600">Mermaid 源码</span>
          </div>
          <pre className="p-4 text-xs text-slate-700 overflow-x-auto max-h-64 overflow-y-auto font-mono whitespace-pre">
            {code}
          </pre>
        </div>
      )}
    </div>
  )
}
