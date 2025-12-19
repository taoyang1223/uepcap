import { useState, useCallback, useEffect, useRef } from 'react'
import { Loader2, BadgeCheck, FileArchive, RefreshCw, Copy, CopyCheck, Download, Clock, PackageOpen } from 'lucide-react'

interface ExportPanelProps {
  jobId: string
  selectedIMSIs: string[]
  selectedProtocols: string[]
}

interface ExportResult {
  task_id?: string
  status: string
  download_url?: string
  filename?: string
  imsi_count: number
  file_count?: number
  filter?: string
  cached?: boolean
}

export function ExportPanel({ jobId, selectedIMSIs, selectedProtocols }: ExportPanelProps) {
  const [exporting, setExporting] = useState(false)
  const [result, setResult] = useState<ExportResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [pcapGenerating, setPcapGenerating] = useState(false)
  const pollingRef = useRef<number | null>(null)

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
      }
    }
  }, [])

  // Poll for export status
  const pollExportStatus = useCallback(async (taskId: string) => {
    try {
      const response = await fetch(`/api/jobs/${jobId}/export/${taskId}/status`)
      const data = await response.json()

      if (data.success) {
        const taskStatus = data.data
        if (taskStatus.status === 'completed') {
          // Stop polling
          if (pollingRef.current) {
            clearInterval(pollingRef.current)
            pollingRef.current = null
          }
          setPcapGenerating(false)
          setResult(prev => ({
            ...prev!,
            status: 'completed',
            download_url: taskStatus.download_url,
            filename: taskStatus.filename,
            file_count: taskStatus.file_count,
          }))
        } else if (taskStatus.status === 'error') {
          if (pollingRef.current) {
            clearInterval(pollingRef.current)
            pollingRef.current = null
          }
          setPcapGenerating(false)
          setError(taskStatus.error || 'PCAP 生成失败')
        }
      }
    } catch (err) {
      console.error('Failed to poll export status:', err)
    }
  }, [jobId])

  const handleExport = useCallback(async () => {
    if (selectedIMSIs.length === 0 || selectedProtocols.length === 0) return

    setExporting(true)
    setError(null)
    setResult(null)
    setPcapGenerating(false)

    // Clear any existing polling
    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }

    try {
      const response = await fetch(`/api/jobs/${jobId}/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imsis: selectedIMSIs,
          protocols: selectedProtocols,
        }),
      })

      const data = await response.json()

      if (data.success) {
        setResult(data.data)
        
        // If it's a cached result, we're done
        if (data.data.cached || data.data.status === 'completed') {
          // Already complete
        } else if (data.data.task_id && data.data.status === 'processing') {
          // Start polling for pcap generation status
          setPcapGenerating(true)
          pollingRef.current = window.setInterval(() => {
            pollExportStatus(data.data.task_id)
          }, 1000) // Poll every second
        }
      } else {
        setError(data.error || '导出失败')
      }
    } catch (err) {
      setError('导出失败: ' + (err as Error).message)
    } finally {
      setExporting(false)
    }
  }, [jobId, selectedIMSIs, selectedProtocols, pollExportStatus])

  const handleDownload = useCallback(() => {
    if (result?.download_url) {
      window.location.href = result.download_url
    }
  }, [result])

  const handleCopyFilter = useCallback(async () => {
    if (!result?.filter) return
    
    try {
      await navigator.clipboard.writeText(result.filter)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy filter:', err)
    }
  }, [result])

  const handleReset = useCallback(() => {
    // Clear polling
    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }
    setResult(null)
    setPcapGenerating(false)
    setError(null)
  }, [])

  const isComplete = result?.status === 'completed' || result?.cached

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 p-6 overflow-hidden relative">
      <h3 className="text-lg font-bold text-slate-800 flex items-center gap-3 mb-5">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-sm">
          <PackageOpen className="w-5 h-5 text-white" />
        </div>
        <span>导出数据包</span>
      </h3>

      {/* Summary */}
      <div className="p-4 bg-slate-50/80 rounded-xl mb-6">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="px-2 text-center">
            <p className="text-slate-500 text-xs uppercase tracking-wider font-semibold mb-1">选中 UE</p>
            <p className="text-indigo-600 font-bold text-2xl">{selectedIMSIs.length}</p>
          </div>
          <div className="px-4 text-center border-l border-slate-200">
            <p className="text-slate-500 text-xs uppercase tracking-wider font-semibold mb-1">协议类型</p>
            <p className="text-slate-700 font-bold text-2xl">{selectedProtocols.length}</p>
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-3 bg-red-50 rounded-xl text-red-700 text-sm flex items-center animate-fade-in">
           <svg className="w-4 h-4 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className={`mb-5 p-4 rounded-xl animate-fade-in ${isComplete ? 'bg-emerald-50/80' : 'bg-blue-50/80'}`}>
          <div className="flex items-center gap-2 mb-3">
            {isComplete ? (
              <>
                <BadgeCheck className="w-5 h-5 text-emerald-600" />
                <span className="font-bold text-emerald-700">生成成功</span>
                {result.cached && <span className="text-xs bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full font-medium">已缓存</span>}
              </>
            ) : (
              <>
                <Clock className="w-5 h-5 text-blue-600" />
                <span className="font-bold text-blue-700">过滤条件已生成</span>
              </>
            )}
          </div>
          
          {/* Filter display and copy button - show immediately */}
          {result.filter && (
            <div className="p-3 bg-white/60 rounded-xl mb-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Wireshark 过滤条件</span>
                <button
                  onClick={handleCopyFilter}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-lg transition-all ${
                    copied 
                      ? 'bg-emerald-100 text-emerald-700' 
                      : 'bg-indigo-50 text-indigo-600 hover:bg-indigo-100'
                  }`}
                >
                  {copied ? (
                    <>
                      <CopyCheck className="w-3.5 h-3.5" />
                      已复制
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      复制
                    </>
                  )}
                </button>
              </div>
              <code className="block text-xs text-slate-600 bg-white p-2.5 rounded-lg overflow-x-auto max-h-24 font-mono break-all shadow-sm">
                {result.filter}
              </code>
            </div>
          )}

          {/* PCAP generation status */}
          {pcapGenerating && (
            <div className="flex items-center gap-3 bg-white p-3 rounded-xl shadow-sm mb-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-600 flex items-center justify-center text-white shadow-sm">
                <Loader2 className="w-5 h-5 animate-spin" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-slate-800 text-sm font-semibold">正在生成 PCAP 文件...</p>
                <p className="text-xs text-slate-500">
                  您可以先复制过滤条件在 Wireshark 中使用
                </p>
              </div>
            </div>
          )}

          {/* Download section - only show when complete */}
          {isComplete && result.filename && (
            <>
              <div className="flex items-center gap-3 bg-white p-3 rounded-xl shadow-sm">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center text-white shadow-sm">
                   <FileArchive className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-slate-800 text-sm font-semibold truncate">{result.filename}</p>
                  <p className="text-xs text-slate-500">
                    包含 {result.imsi_count} 个 IMSI 的过滤数据
                  </p>
                </div>
              </div>

              <button
                onClick={handleDownload}
                className="w-full mt-4 py-2.5 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 text-white font-semibold rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 active:scale-[0.98]"
              >
                <Download className="w-4 h-4" />
                立即下载
              </button>
            </>
          )}
        </div>
      )}

      {/* Export Button */}
      {!result && (
        <button
          onClick={handleExport}
          disabled={exporting || selectedIMSIs.length === 0 || selectedProtocols.length === 0}
          className="w-full py-3.5 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 disabled:from-slate-300 disabled:to-slate-400 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/25 hover:shadow-indigo-500/35 active:scale-[0.98]"
        >
          {exporting ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              正在解析过滤条件...
            </>
          ) : (
            <>
              <PackageOpen className="w-5 h-5" />
              开始导出
            </>
          )}
        </button>
      )}

      {/* Reset */}
      {result && (
        <button
          onClick={handleReset}
          className="w-full py-3 text-slate-400 hover:text-indigo-600 transition-colors text-sm flex items-center justify-center gap-1.5 font-medium"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          重新生成
        </button>
      )}
    </div>
  )
}
