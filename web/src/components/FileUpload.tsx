import { useState, useCallback, useRef } from 'react'
import { FileArchive, X, Loader2, CloudUpload } from 'lucide-react'

interface FileUploadProps {
  onUploadComplete: (jobId: string, fileCount: number) => void
}

export function FileUpload({ onUploadComplete }: FileUploadProps) {
  const [files, setFiles] = useState<File[]>([])
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [dragOver, setDragOver] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFiles = useCallback((newFiles: FileList | null) => {
    if (!newFiles) return
    
    const pcapFiles = Array.from(newFiles).filter(f => 
      f.name.endsWith('.pcap') || f.name.endsWith('.pcapng') || f.name.endsWith('.cap')
    )
    
    if (pcapFiles.length === 0) {
      setError('请选择 .pcap, .pcapng 或 .cap 文件')
      return
    }
    
    setFiles(prev => [...prev, ...pcapFiles])
    setError(null)
  }, [])

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
        if (xhr.status === 200) {
          const data = JSON.parse(xhr.responseText)
          if (data.success) {
            onUploadComplete(data.data.job_id, data.data.file_count)
          } else {
            setError(data.error || '上传失败')
          }
        } else {
          setError('上传失败: HTTP ' + xhr.status)
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

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  return (
    <div className="bg-white rounded-2xl shadow-xl shadow-slate-900/5 p-8">
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
          accept=".pcap,.pcapng,.cap"
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
          支持上传多个 .pcap, .pcapng 文件，系统将自动合并处理
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
          <p className="text-sm font-medium text-slate-500 mb-3 px-1">已选择 {files.length} 个文件：</p>
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
                正在上传并合并... <span className="text-slate-900">{progress}%</span>
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
  )
}
