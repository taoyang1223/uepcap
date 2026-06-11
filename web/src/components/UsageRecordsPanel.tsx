import { Clock3, FileArchive, History, RefreshCw, Trash2, X } from 'lucide-react'

export interface UsageRecordFile {
  name: string
  size: number
}

export interface UsageRecord {
  id: string
  job_id: string
  created_at: string
  file_count: number
  total_size: number
  files: UsageRecordFile[]
}

interface UsageRecordsPanelProps {
  records: UsageRecord[]
  loading: boolean
  error: string | null
  deletingId: string | null
  clearing: boolean
  onRefresh: () => void
  onRemove: (id: string) => void
  onClear: () => void
}

export function UsageRecordsPanel({
  records,
  loading,
  error,
  deletingId,
  clearing,
  onRefresh,
  onRemove,
  onClear,
}: UsageRecordsPanelProps) {
  return (
    <aside className="xl:sticky xl:top-24 xl:h-fit">
      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm shadow-slate-900/5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-800">
              <History className="h-4 w-4 text-indigo-500" />
              <span>今日使用记录</span>
              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-bold text-slate-500">{records.length}/10</span>
            </div>
            <p className="mt-1 text-xs font-medium text-slate-400">仅保留当天最新 10 条</p>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={onClear}
              disabled={loading || clearing || records.length === 0}
              className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-red-50 hover:text-red-600 disabled:cursor-not-allowed disabled:opacity-50"
              aria-label="清空今日使用记录"
              title="清空"
            >
              <Trash2 className={`h-4 w-4 ${clearing ? 'animate-pulse' : ''}`} />
            </button>
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading || clearing}
              className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-indigo-50 hover:text-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
              aria-label="刷新今日使用记录"
              title="刷新"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {error ? (
          <div className="rounded-lg bg-red-50 px-3 py-2 text-xs font-medium text-red-700">
            {error}
          </div>
        ) : records.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 px-3 py-8 text-center text-sm font-medium text-slate-400">
            {loading ? '正在读取...' : '今天暂无记录'}
          </div>
        ) : (
          <div className="max-h-[520px] space-y-2 overflow-y-auto pr-1 custom-scrollbar">
            {records.map(record => (
              <article
                key={record.id || record.job_id}
                className="relative rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-3 transition-colors hover:border-indigo-200 hover:bg-indigo-50/40"
              >
                <button
                  type="button"
                  onClick={() => onRemove(record.id || record.job_id)}
                  disabled={loading || clearing || deletingId === record.id || deletingId === record.job_id}
                  className="absolute right-2 top-2 rounded-md bg-white/90 p-1 text-slate-400 shadow-sm ring-1 ring-slate-200 transition-colors hover:bg-red-100 hover:text-red-600 hover:ring-red-100 disabled:cursor-not-allowed disabled:opacity-50"
                  aria-label={`删除 ${usageRecordTitle(record)}`}
                  title="删除"
                >
                  <X className={`h-3.5 w-3.5 ${deletingId === record.id || deletingId === record.job_id ? 'animate-pulse' : ''}`} />
                </button>
                <div className="flex items-start gap-3 pr-6">
                  <span className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-white text-indigo-500 shadow-sm ring-1 ring-slate-200">
                    <FileArchive className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <h3 className="truncate text-sm font-bold text-slate-800">{usageRecordTitle(record)}</h3>
                    <p className="mt-1 truncate text-xs font-medium text-slate-500">
                      {record.file_count} 个文件 · {formatSize(record.total_size)}
                    </p>
                    <div className="mt-2 flex items-center justify-between gap-2 text-[11px] font-semibold text-slate-400">
                      <span className="flex items-center gap-1">
                        <Clock3 className="h-3 w-3" />
                        {formatUsageRecordTime(record.created_at)}
                      </span>
                      <span className="truncate font-mono">Job {record.job_id.slice(0, 8)}</span>
                    </div>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </aside>
  )
}

function usageRecordTitle(record: UsageRecord) {
  if (!record.files || record.files.length === 0) return `${record.file_count} 个抓包文件`
  if (record.files.length === 1) return record.files[0].name
  return `${record.files[0].name} 等 ${record.file_count} 个文件`
}

function formatUsageRecordTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '时间未知'
  return date.toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

function formatSize(bytes: number) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
}
