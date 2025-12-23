import { useRef, useState, useEffect, useCallback, type ReactNode, type PointerEvent as ReactPointerEvent } from 'react'
import { X, GripHorizontal } from 'lucide-react'

interface DraggableWindowProps {
  title: string
  subtitle?: string
  children: ReactNode
  onClose: () => void
  /** Initial position (defaults to center of viewport) */
  initialPosition?: { x: number; y: number }
  /** Minimum width in pixels */
  minWidth?: number
  /** Minimum height in pixels */
  minHeight?: number
}

export function DraggableWindow({
  title,
  subtitle,
  children,
  onClose,
  initialPosition,
  minWidth = 400,
  minHeight = 200,
}: DraggableWindowProps) {
  const windowRef = useRef<HTMLDivElement>(null)
  const dragStartRef = useRef<{ x: number; y: number; posX: number; posY: number } | null>(null)

  // Initialize position: center of viewport if not provided
  const [pos, setPos] = useState<{ x: number; y: number }>(() => {
    if (initialPosition) return initialPosition
    // Will be adjusted after mount
    return { x: 100, y: 100 }
  })

  // Center the window on mount if no initial position
  useEffect(() => {
    if (!initialPosition && windowRef.current) {
      const rect = windowRef.current.getBoundingClientRect()
      const x = Math.max(20, (window.innerWidth - rect.width) / 2)
      const y = Math.max(20, (window.innerHeight - rect.height) / 3)
      setPos({ x, y })
    }
  }, [initialPosition])

  // ESC key to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  // Pointer move handler (attached to window)
  const handlePointerMove = useCallback((e: globalThis.PointerEvent) => {
    if (!dragStartRef.current) return
    const dx = e.clientX - dragStartRef.current.x
    const dy = e.clientY - dragStartRef.current.y
    let newX = dragStartRef.current.posX + dx
    let newY = dragStartRef.current.posY + dy

    // Boundary constraints: keep at least 50px visible
    const maxX = window.innerWidth - 50
    const maxY = window.innerHeight - 50
    newX = Math.max(-50, Math.min(newX, maxX))
    newY = Math.max(0, Math.min(newY, maxY))

    setPos({ x: newX, y: newY })
  }, [])

  const handlePointerUp = useCallback(() => {
    dragStartRef.current = null
    window.removeEventListener('pointermove', handlePointerMove)
    window.removeEventListener('pointerup', handlePointerUp)
  }, [handlePointerMove])

  const handlePointerDown = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      // Only left button
      if (e.button !== 0) return
      e.preventDefault()
      dragStartRef.current = { x: e.clientX, y: e.clientY, posX: pos.x, posY: pos.y }
      window.addEventListener('pointermove', handlePointerMove)
      window.addEventListener('pointerup', handlePointerUp)
    },
    [pos.x, pos.y, handlePointerMove, handlePointerUp]
  )

  return (
    <div
      ref={windowRef}
      className="fixed z-[60] bg-white rounded-xl border border-slate-200 shadow-2xl flex flex-col overflow-hidden"
      style={{
        left: pos.x,
        top: pos.y,
        minWidth,
        minHeight,
        maxWidth: 'calc(100vw - 40px)',
        maxHeight: 'calc(100vh - 40px)',
      }}
    >
      {/* Draggable header */}
      <div
        onPointerDown={handlePointerDown}
        className="flex items-center justify-between gap-3 px-4 py-3 bg-gradient-to-r from-violet-500 to-purple-600 cursor-move select-none"
      >
        <div className="flex items-center gap-2 min-w-0">
          <GripHorizontal className="w-4 h-4 text-white/70 flex-shrink-0" />
          <div className="min-w-0">
            <div className="text-white font-semibold text-sm truncate">{title}</div>
            {subtitle && <div className="text-white/80 text-xs truncate">{subtitle}</div>}
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 hover:bg-white/20 rounded-lg transition-colors flex-shrink-0"
          title="关闭 (ESC)"
        >
          <X className="w-4 h-4 text-white" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">{children}</div>
    </div>
  )
}

