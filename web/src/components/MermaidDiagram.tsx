import { useEffect, useRef, useState, useId, useCallback } from 'react'
import mermaid from 'mermaid'
import { AlertCircle, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react'

// Initialize mermaid with optimized settings for sequence diagrams with long messages
mermaid.initialize({
  startOnLoad: false,
  // 使用 'loose' 以支持 <br/> 等 HTML 标签在消息中渲染
  securityLevel: 'loose',
  theme: 'default',
  sequence: {
    diagramMarginX: 80,
    diagramMarginY: 30,
    // 大幅增加 actor 间距以容纳长消息文本
    actorMargin: 300,
    // 增加 actor 宽度
    width: 180,
    height: 65,
    boxMargin: 15,
    boxTextMargin: 8,
    noteMargin: 20,
    // 增加消息间距以容纳多行文本
    messageMargin: 60,
    mirrorActors: true,
    // 禁用 useMaxWidth，让图表可以水平滚动
    useMaxWidth: false,
    rightAngles: false,
    showSequenceNumbers: true,
    // 增加消息文本的包裹宽度
    wrapPadding: 15,
    wrap: true,
    // 增加 message 文本字号
    messageFontSize: 13,
    // Note 相关设置
    noteFontSize: 10,
  },
  // 全局字体设置
  fontFamily: 'ui-sans-serif, system-ui, sans-serif',
  fontSize: 12,
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

  const applyHighlight = useCallback(() => {
    const container = containerRef.current
    if (!container) return
    const svg = container.querySelector('svg')
    if (!svg) return

    const textEls = Array.from(svg.querySelectorAll<SVGTextElement>('text.messageText'))
    const lineEls = Array.from(svg.querySelectorAll<SVGPathElement>('path.messageLine0, path.messageLine1'))

    // Reset classes
    for (const el of [...textEls, ...lineEls]) {
      el.classList.remove('uepcap-highlight')
      el.classList.remove('uepcap-dim')
    }

    if (!highlightMessageIndex || highlightMessageIndex <= 0) return
    const target = highlightMessageIndex - 1

    textEls.forEach((el, i) => el.classList.add(i === target ? 'uepcap-highlight' : 'uepcap-dim'))
    lineEls.forEach((el, i) => el.classList.add(i === target ? 'uepcap-highlight' : 'uepcap-dim'))
  }, [highlightMessageIndex])

  const resolveMessageIndexFromTarget = useCallback((targetEl: Element) => {
    const container = containerRef.current
    if (!container) return null
    const svg = container.querySelector('svg')
    if (!svg) return null

    const textEls = Array.from(svg.querySelectorAll<SVGTextElement>('text.messageText'))
    if (!textEls.length) return null

    const messageTextEl = targetEl.closest('text.messageText')
    if (messageTextEl) {
      const idx = textEls.indexOf(messageTextEl as SVGTextElement)
      return idx >= 0 ? idx + 1 : null
    }

    const lineEl = targetEl.closest('path.messageLine0, path.messageLine1')
    if (lineEl) {
      // Best-effort: try to find a messageText in the same group
      const g = (lineEl as Element).closest('g')
      if (g) {
        const siblingText = g.querySelector('text.messageText')
        if (siblingText) {
          const idx = textEls.indexOf(siblingText as SVGTextElement)
          return idx >= 0 ? idx + 1 : null
        }
      }

      // Fallback: if line count matches text count, map by order
      const lineEls = Array.from(svg.querySelectorAll<SVGPathElement>('path.messageLine0, path.messageLine1'))
      if (lineEls.length === textEls.length) {
        const idx = lineEls.indexOf(lineEl as SVGPathElement)
        return idx >= 0 ? idx + 1 : null
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

  // Preprocess Mermaid code to wrap long Note text with <br/> tags
  const preprocessCode = useCallback((rawCode: string): string => {
    const MAX_LINE_LENGTH = 60 // Max characters per line in notes
    
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

      // 📌 Log: 原始点击目标
      console.log('[MermaidDiagram] 🖱️ SVG Click Event:', {
        targetElement: t.tagName,
        targetClass: t.className,
        targetText: t.textContent?.substring(0, 50),
      })

      const messageIdx = resolveMessageIndexFromTarget(t)
      if (messageIdx) {
        // 📌 Log: 解析出的消息索引
        console.log('[MermaidDiagram] ✅ Message Click Detected:', {
          messageIndex: messageIdx,
          hasCallback: !!onMessageClick,
        })
        if (onMessageClick) {
          onMessageClick(messageIdx)
        }
        return
      }

      const actorName = resolveActorNameFromTarget(t)
      if (actorName) {
        // 📌 Log: 解析出的 Actor 名称
        console.log('[MermaidDiagram] ✅ Actor Click Detected:', {
          actorName,
          hasCallback: !!onActorClick,
        })
        if (onActorClick) {
          onActorClick(actorName)
        }
        return
      }

      // 📌 Log: 未识别的点击
      console.log('[MermaidDiagram] ⚠️ Click not recognized as message or actor')
    }

    svg.addEventListener('click', handler)
    console.log('[MermaidDiagram] 🎯 Click handler attached to SVG')
    return () => {
      svg.removeEventListener('click', handler)
      console.log('[MermaidDiagram] 🎯 Click handler removed from SVG')
    }
  }, [svgReady, onActorClick, onMessageClick, resolveActorNameFromTarget, resolveMessageIndexFromTarget])

  // Update highlight without re-rendering the diagram
  useEffect(() => {
    applyHighlight()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightMessageIndex])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code)
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
      {/* Diagram container */}
      <div
        ref={containerRef}
        className="mermaid-container overflow-x-auto overflow-y-auto bg-white rounded-xl border border-slate-200 p-4"
        style={{ 
          minHeight: 200,
          maxHeight: '80vh',
        }}
      />
      
      {/* CSS for mermaid message text - enhanced for long messages */}
      <style>{`
        .mermaid-container .messageText {
          font-size: 13px !important;
          fill: #1f2937 !important;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
        }
        .mermaid-container .messageText tspan {
          font-size: 13px !important;
          fill: #1f2937 !important;
        }
        .mermaid-container text.messageText {
          dominant-baseline: middle !important;
          text-anchor: start !important;
        }
        .mermaid-container .actor {
          font-size: 12px !important;
          font-weight: 600 !important;
        }
        .mermaid-container .actor-box {
          fill: #f8fafc !important;
          stroke: #94a3b8 !important;
        }
        .mermaid-container .note {
          font-size: 11px !important;
          fill: #fef3c7 !important;
        }
        .mermaid-container .noteText {
          font-size: 11px !important;
          fill: #92400e !important;
        }
        .mermaid-container .labelText {
          font-size: 10px !important;
        }
        .mermaid-container svg {
          max-width: none !important;
        }
        .mermaid-container .messageLine0,
        .mermaid-container .messageLine1 {
          stroke: #6366f1 !important;
          stroke-width: 1.5 !important;
        }
        .mermaid-container text.messageText,
        .mermaid-container .messageLine0,
        .mermaid-container .messageLine1,
        .mermaid-container text.actor,
        .mermaid-container .actor-box {
          cursor: pointer;
        }
        .mermaid-container .arrowhead {
          fill: #6366f1 !important;
        }
        .mermaid-container .sequenceNumber {
          fill: white !important;
          font-size: 10px !important;
          font-weight: 600 !important;
        }
        .mermaid-container rect.sequenceNumber {
          fill: #6366f1 !important;
        }
        .mermaid-container .uepcap-highlight {
          opacity: 1 !important;
          filter: drop-shadow(0 0 6px rgba(99, 102, 241, 0.35));
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

