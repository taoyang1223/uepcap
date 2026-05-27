export interface StreamProgress {
  processed_messages?: number
  chunk_index?: number
  chunk_messages?: number
  chunk_target?: number
  done?: boolean
}

interface StreamProgressBarProps {
  progress: StreamProgress | null
  label: string
  unit?: string
}

export function StreamProgressBar({ progress, label, unit = '条' }: StreamProgressBarProps) {
  const chunkMessages = progress?.chunk_messages || 0
  const chunkTarget = progress?.chunk_target || 5000
  const percent = Math.min(100, Math.round((chunkMessages / chunkTarget) * 100))
  return (
    <div className="mb-6 rounded-xl border border-cyan-100 bg-cyan-50 px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-3 text-sm font-semibold text-cyan-800">
        <span>{label}</span>
        <span className="shrink-0">第 {progress?.chunk_index || 1} 批 · 已处理 {formatCount(progress?.processed_messages || 0)} {unit}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-white">
        <div className="h-full rounded-full bg-cyan-600 transition-all duration-300" style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}

function formatCount(value: number): string {
  return new Intl.NumberFormat('zh-CN').format(value)
}
