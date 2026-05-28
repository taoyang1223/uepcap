import { useState, useCallback, useRef } from 'react'
import { Check, FileArchive, X, Loader2, CloudUpload, History, Pencil, Trash2 } from 'lucide-react'
import type { RecentImport, RecentImportFile } from '../utils/recentImports'
import { formatRecentImportTime, recentImportTitle } from '../utils/recentImports'

interface FileUploadProps {
  onUploadComplete: (jobId: string, fileCount: number, uploadedFiles: RecentImportFile[]) => void
  recentImports: RecentImport[]
  onRecentImportSelect: (item: RecentImport) => void
  onRecentImportRemove: (id: string) => void
  onRecentImportRename: (id: string, name: string) => void
  onRecentImportsClear: () => void
}

const pcapFilenamePattern = /\.(pcap\d*|pcapng|cap)$/i
const largeUploadThreshold = 300 * 1024 * 1024
const maxUploadBytes = 2 * 1024 * 1024 * 1024

export function FileUpload({
  onUploadComplete,
  recentImports,
  onRecentImportSelect,
  onRecentImportRemove,
  onRecentImportRename,
  onRecentImportsClear,
}: FileUploadProps) {
  const [files, setFiles] = useState<File[]>([])
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [dragOver, setDragOver] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFiles = useCallback((newFiles: FileList | null) => {
    if (!newFiles) return
    
    const pcapFiles = Array.from(newFiles).filter(f => pcapFilenamePattern.test(f.name))
    
    if (pcapFiles.length === 0) {
      setError('请选择 .pcap、.pcap1、.pcapng 或 .cap 文件')
      return
    }

    const nextFiles = [...files, ...pcapFiles]
    const totalSize = nextFiles.reduce((sum, file) => sum + file.size, 0)
    if (totalSize > maxUploadBytes) {
      setError(`文件总大小 ${formatSize(totalSize)} 超过上限 ${formatSize(maxUploadBytes)}`)
      return
    }
    
    setFiles(nextFiles)
    setError(null)
  }, [files])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    handleFiles(e.dataTransfer.files)
  }, [handleFiles])

  const removeFile = useCallback((index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index))
  }, [])

  const handleUpload = useCallback(async () => {
    if (files.length === 0) return

    setUploading(true)
    setProgress(0)
    setError(null)

    const formData = new FormData()
    files.forEach(file => formData.append('files', file))

    try {
      const xhr = new XMLHttpRequest()
      
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          setProgress(Math.round((e.loaded / e.total) * 100))
        }
      }

      xhr.onload = () => {
        let data: any = null
        try {
          data = xhr.responseText ? JSON.parse(xhr.responseText) : null
        } catch {
          data = null
        }
        if (xhr.status === 200) {
          if (data.success) {
            onUploadComplete(
              data.data.job_id,
              data.data.file_count,
              files.map(file => ({ name: file.name, size: file.size })),
            )
          } else {
            setError(data.error || '上传失败')
          }
        } else if (xhr.status === 413) {
          setError(data?.error || `上传失败：文件总大小超过 ${formatSize(maxUploadBytes)}`)
        } else {
          setError(data?.error || '上传失败: HTTP ' + xhr.status)
        }
        setUploading(false)
      }

      xhr.onerror = () => {
        setError('网络错误，请重试')
        setUploading(false)
      }

      xhr.open('POST', '/api/jobs')
      xhr.send(formData)
    } catch (err) {
      setError('上传失败: ' + (err as Error).message)
      setUploading(false)
    }
  }, [files, onUploadComplete])

  const totalSize = files.reduce((sum, file) => sum + file.size, 0)
  const hasLargeUpload = totalSize >= largeUploadThreshold
  const hasRecentImports = recentImports.length > 0

  return (
    <div className={`overflow-hidden bg-white rounded-2xl shadow-xl shadow-slate-900/5 ${hasRecentImports ? 'flex flex-col lg:grid lg:grid-cols-[320px_minmax(0,1fr)]' : 'p-8'}`}>
      {hasRecentImports && (
        <div className="order-2 border-t border-slate-100 p-6 lg:order-1 lg:border-r lg:border-t-0">
          <RecentImportList
            items={recentImports}
            disabled={uploading}
            onSelect={onRecentImportSelect}
            onRemove={onRecentImportRemove}
            onRename={onRecentImportRename}
            onClear={onRecentImportsClear}
          />
        </div>
      )}

      <div className={hasRecentImports ? 'order-1 p-6 lg:order-2 lg:p-8' : ''}>
        {/* Drop Zone */}
        <div
          className={`
            relative border-2 border-dashed rounded-xl p-10 text-center transition-all cursor-pointer group
            ${dragOver
              ? 'border-indigo-400 bg-indigo-50/50'
              : 'border-slate-200 hover:border-indigo-300 hover:bg-slate-50/50'
            }
          `}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => handleFiles(e.target.files)}
          />

          <div className={`w-16 h-16 mx-auto mb-4 rounded-2xl flex items-center justify-center transition-all duration-300 ${dragOver ? 'bg-indigo-500 text-white scale-110 shadow-lg shadow-indigo-500/30' : 'bg-gradient-to-br from-indigo-500 to-purple-600 text-white group-hover:scale-110 shadow-lg shadow-indigo-500/20'}`}>
            <CloudUpload className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-semibold text-slate-800 mb-2">
            点击或拖拽文件到此处
          </h3>
          <p className="text-sm text-slate-500 max-w-xs mx-auto">
            支持上传多个 .pcap、.pcap1、.pcapng 文件，系统将自动合并处理
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="mt-6 p-3 bg-red-50 rounded-xl text-red-700 text-sm flex items-center">
            <svg className="w-4 h-4 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>
            {error}
          </div>
        )}

        {/* File List */}
        {files.length > 0 && (
          <div className="mt-8 space-y-3 animate-fade-in">
            <p className="text-sm font-medium text-slate-500 mb-3 px-1">已选择 {files.length} 个文件，总大小 {formatSize(totalSize)}：</p>
            {hasLargeUpload && (
              <div className="rounded-xl bg-amber-50 px-3 py-2 text-sm text-amber-800">
                大文件会使用流式上传并直接写入磁盘，上传后扫描 IMSI 可能需要几分钟，请保持页面打开。
              </div>
            )}
            <div className="max-h-60 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
              {files.map((file, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 bg-slate-50/80 rounded-xl group hover:bg-indigo-50/50 transition-all duration-200"
                >
                  <div className="flex items-center gap-3 overflow-hidden">
                    <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white flex-shrink-0 shadow-sm">
                      <FileArchive className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-slate-700 truncate">{file.name}</p>
                      <p className="text-xs text-slate-500">{formatSize(file.size)}</p>
                    </div>
                  </div>
                  {!uploading && (
                    <button
                      onClick={(e) => { e.stopPropagation(); removeFile(index) }}
                      className="p-1.5 hover:bg-red-100 hover:text-red-600 rounded-md text-slate-400 transition-colors opacity-0 group-hover:opacity-100"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Upload Button */}
        {files.length > 0 && (
          <div className="mt-8">
            {uploading ? (
              <div className="space-y-3">
                <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-indigo-600 transition-all duration-300 ease-out rounded-full"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <p className="text-sm text-slate-500 text-center flex items-center justify-center gap-2 font-medium">
                  <Loader2 className="w-4 h-4 animate-spin text-indigo-600" />
                  {hasLargeUpload ? '正在流式上传大文件...' : '正在上传并合并...'} <span className="text-slate-900">{progress}%</span>
                </p>
              </div>
            ) : (
              <button
                onClick={handleUpload}
                className="w-full py-3.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-xl transition-all shadow-lg shadow-indigo-600/30 hover:shadow-indigo-600/40 active:scale-[0.99] transform hover:-translate-y-0.5"
              >
                开始处理 ({files.length} 个文件)
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

interface RecentImportListProps {
  items: RecentImport[]
  disabled: boolean
  onSelect: (item: RecentImport) => void
  onRemove: (id: string) => void
  onRename: (id: string, name: string) => void
  onClear: () => void
}

function RecentImportList({ items, disabled, onSelect, onRemove, onRename, onClear }: RecentImportListProps) {
  const [editingId, setEditingId] = useState<string | null>(null)
  const [draftName, setDraftName] = useState('')

  const startRename = useCallback((item: RecentImport) => {
    setEditingId(item.id)
    setDraftName(recentImportTitle(item))
  }, [])

  const cancelRename = useCallback(() => {
    setEditingId(null)
    setDraftName('')
  }, [])

  const submitRename = useCallback((id: string) => {
    const nextName = draftName.trim()
    if (nextName !== '') {
      onRename(id, nextName)
    }
    cancelRename()
  }, [cancelRename, draftName, onRename])

  return (
    <div className="space-y-4">
      <div className="mb-3 flex items-center justify-between gap-3 px-1">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-700">
          <History className="h-4 w-4 text-indigo-500" />
          <span>最近导入</span>
          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-bold text-slate-500">{items.length}/10</span>
        </div>
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation()
            onClear()
          }}
          className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-bold text-slate-500 transition-colors hover:bg-red-50 hover:text-red-600"
        >
          <Trash2 className="h-3.5 w-3.5" />
          清空
        </button>
      </div>
      <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1 custom-scrollbar">
        {items.map(item => (
          <div
            key={item.id}
            className="group relative min-h-24 rounded-xl border border-slate-200 bg-slate-50/80 px-3 py-3 text-left transition-all hover:border-indigo-200 hover:bg-indigo-50/60 hover:shadow-sm"
          >
            {editingId === item.id ? (
              <div className="flex items-start gap-3 pr-1">
                <span className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl bg-white text-indigo-500 shadow-sm ring-1 ring-slate-200">
                  <FileArchive className="h-4 w-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <input
                    value={draftName}
                    autoFocus
                    onChange={event => setDraftName(event.target.value)}
                    onKeyDown={event => {
                      if (event.key === 'Enter') submitRename(item.id)
                      if (event.key === 'Escape') cancelRename()
                    }}
                    className="w-full rounded-lg border border-indigo-200 bg-white px-2.5 py-1.5 text-sm font-bold text-slate-800 outline-none ring-2 ring-transparent transition focus:ring-indigo-500/20"
                  />
                  <div className="mt-2 flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => submitRename(item.id)}
                      className="inline-flex items-center gap-1 rounded-md bg-indigo-600 px-2 py-1 text-xs font-bold text-white hover:bg-indigo-700"
                    >
                      <Check className="h-3.5 w-3.5" />
                      保存
                    </button>
                    <button
                      type="button"
                      onClick={cancelRename}
                      className="inline-flex items-center gap-1 rounded-md bg-slate-100 px-2 py-1 text-xs font-bold text-slate-500 hover:bg-slate-200 hover:text-slate-700"
                    >
                      <X className="h-3.5 w-3.5" />
                      取消
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <>
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => onSelect(item)}
                  className="block h-full w-full pr-14 text-left disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <span className="flex items-start gap-3">
                    <span className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl bg-white text-indigo-500 shadow-sm ring-1 ring-slate-200">
                      <FileArchive className="h-4 w-4" />
                    </span>
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-bold text-slate-800">{recentImportTitle(item)}</span>
                      <span className="mt-1 block truncate text-xs font-medium text-slate-500">
                        {item.fileCount} 个文件 · {formatSize(item.totalSize)} · {formatRecentImportTime(item.importedAt)}
                      </span>
                      <span className="mt-2 block truncate font-mono text-[11px] font-semibold text-slate-400">
                        Job {item.jobId.slice(0, 8)}
                      </span>
                    </span>
                  </span>
                </button>
                <div className="absolute right-2 top-2 flex items-center gap-1">
                  <button
                    type="button"
                    aria-label={`重命名 ${recentImportTitle(item)}`}
                    onClick={(event) => {
                      event.preventDefault()
                      event.stopPropagation()
                      startRename(item)
                    }}
                    className="rounded-md bg-white/80 p-1 text-slate-400 shadow-sm ring-1 ring-slate-200 transition-all hover:bg-indigo-100 hover:text-indigo-600 hover:ring-indigo-100"
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    aria-label={`删除 ${recentImportTitle(item)}`}
                    onClick={(event) => {
                      event.preventDefault()
                      event.stopPropagation()
                      onRemove(item.id)
                    }}
                    className="rounded-md bg-white/80 p-1 text-slate-400 shadow-sm ring-1 ring-slate-200 transition-all hover:bg-red-100 hover:text-red-600 hover:ring-red-100"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function formatSize(bytes: number) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
}
