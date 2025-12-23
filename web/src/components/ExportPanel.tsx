import { useState, useCallback, useEffect, useRef } from 'react'
import { Loader2, BadgeCheck, FileArchive, RefreshCw, Copy, CopyCheck, Download, Clock, PackageOpen, FileText, ClipboardCopy, Eye } from 'lucide-react'
import { FlowSummaryCard } from './FlowSummaryCard'

// 安全的剪贴板复制函数，带 fallback
async function copyToClipboard(text: string): Promise<boolean> {
  // 首先尝试使用现代 Clipboard API
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch (err) {
      console.warn('Clipboard API failed, trying fallback:', err)
    }
  }
  
  // Fallback: 使用传统的 execCommand 方法
  const textArea = document.createElement('textarea')
  textArea.value = text
  textArea.style.position = 'fixed'
  textArea.style.left = '-999999px'
  textArea.style.top = '-999999px'
  document.body.appendChild(textArea)
  textArea.focus()
  textArea.select()
  
  try {
    const success = document.execCommand('copy')
    document.body.removeChild(textArea)
    return success
  } catch (err) {
    console.error('Fallback copy failed:', err)
    document.body.removeChild(textArea)
    return false
  }
}

interface ExportPanelProps {
  jobId: string
  selectedIMSIs: string[]
  selectedProtocols: string[]
  onViewTimeline?: (packets: any[]) => void
  onViewFlow?: (filter: string) => void
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

export function ExportPanel({ jobId, selectedIMSIs, selectedProtocols, onViewTimeline, onViewFlow }: ExportPanelProps) {
  const [exporting, setExporting] = useState(false)
  const [result, setResult] = useState<ExportResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [pcapGenerating, setPcapGenerating] = useState(false)
  const pollingRef = useRef<number | null>(null)

  // 数据包文本相关状态
  const [textExporting, setTextExporting] = useState(false)
  const [textCopied, setTextCopied] = useState(false)
  const [textCached, setTextCached] = useState(false)
  const [viewLoading, setViewLoading] = useState(false)

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
    
    const success = await copyToClipboard(result.filter)
    if (success) {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } else {
      setError('复制失败，请手动选择文本复制')
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
    setTextCopied(false)
    setTextCached(false)
  }, [])

  // 获取数据包文本（JSON格式）- 复用函数
  const fetchPacketText = useCallback(async (): Promise<{ text: string; cached: boolean } | null> => {
    if (!result?.filter) return null
    
    try {
      const response = await fetch(`/api/jobs/${jobId}/export/text`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filter: result.filter }),
      })
      
      const data = await response.json()
      
      if (data.success && data.data?.text) {
        return { text: data.data.text, cached: data.data.cached === true }
      } else {
        throw new Error(data.error || '导出数据包文本失败')
      }
    } catch (err) {
      throw err
    }
  }, [jobId, result])

  // 复制数据包文本（JSON格式）
  const handleCopyPacketText = useCallback(async () => {
    if (!result?.filter) return
    
    setTextExporting(true)
    setError(null)
    
    try {
      const data = await fetchPacketText()
      if (data) {
        const success = await copyToClipboard(data.text)
        if (success) {
          setTextCopied(true)
          setTextCached(data.cached)
          setTimeout(() => setTextCopied(false), 2000)
        } else {
          setError('复制失败，请使用下载功能')
        }
      }
    } catch (err) {
      setError('导出失败: ' + (err as Error).message)
    } finally {
      setTextExporting(false)
    }
  }, [result, fetchPacketText])

  // 下载数据包文本（JSON格式）
  const handleDownloadPacketText = useCallback(async () => {
    if (!result?.filter) return
    
    setTextExporting(true)
    setError(null)
    
    try {
      const response = await fetch(`/api/jobs/${jobId}/export/text/download`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filter: result.filter }),
      })
      
      if (!response.ok) {
        const data = await response.json()
        setError(data.error || '下载失败')
        return
      }
      
      // 获取文件名
      const contentDisposition = response.headers.get('Content-Disposition')
      let filename = 'packets_export.json'
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?([^"]+)"?/)
        if (match) filename = match[1]
      }
      
      // 下载文件
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError('下载失败: ' + (err as Error).message)
    } finally {
      setTextExporting(false)
    }
  }, [jobId, result])

  // 查看时间线可视化
  const handleViewTimeline = useCallback(async () => {
    if (!result?.filter || !onViewTimeline) return
    
    setViewLoading(true)
    setError(null)
    
    try {
      const data = await fetchPacketText()
      if (data) {
        // 解析 JSON 字符串为数组
        const packets = JSON.parse(data.text)
        if (Array.isArray(packets)) {
          onViewTimeline(packets)
        } else {
          setError('数据格式错误')
        }
      }
    } catch (err) {
      setError('加载失败: ' + (err as Error).message)
    } finally {
      setViewLoading(false)
    }
  }, [result, fetchPacketText, onViewTimeline])

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

              {/* 数据包文本操作按钮 */}
              <div className="grid grid-cols-2 gap-3 mt-4 border-t border-slate-100 pt-4">
                <button
                  onClick={handleCopyPacketText}
                  disabled={textExporting || viewLoading}
                  className={`group py-2.5 px-3 font-medium text-sm rounded-xl transition-all duration-200 flex items-center justify-center gap-2 border active:scale-[0.98] ${
                    textCopied
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200 shadow-sm'
                      : 'bg-white text-slate-600 border-slate-200 hover:border-indigo-300 hover:text-indigo-600 hover:shadow-md hover:shadow-indigo-500/5'
                  }`}
                >
                  {textExporting ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : textCopied ? (
                    <CopyCheck className="w-4 h-4" />
                  ) : (
                    <ClipboardCopy className="w-4 h-4 text-slate-400 group-hover:text-indigo-500 transition-colors" />
                  )}
                  <span>{textCopied ? (textCached ? '已复制(缓存)' : '已复制文本') : '复制简要 JSON'}</span>
                </button>
                
                <button
                  onClick={handleDownloadPacketText}
                  disabled={textExporting || viewLoading}
                  className="group py-2.5 px-3 bg-white text-slate-600 hover:text-indigo-600 border border-slate-200 hover:border-indigo-300 font-medium text-sm rounded-xl transition-all duration-200 flex items-center justify-center gap-2 hover:shadow-md hover:shadow-indigo-500/5 active:scale-[0.98]"
                >
                  {textExporting ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <FileText className="w-4 h-4 text-slate-400 group-hover:text-indigo-500 transition-colors" />
                  )}
                  <span>下载 JSON 文本</span>
                </button>
              </div>

              {/* 内容展示按钮 */}
              {onViewTimeline && (
                <button
                  onClick={handleViewTimeline}
                  disabled={textExporting || viewLoading}
                  className="w-full mt-3 py-2.5 px-3 bg-gradient-to-r from-violet-500 to-purple-600 hover:from-violet-600 hover:to-purple-700 disabled:from-slate-300 disabled:to-slate-400 text-white font-semibold text-sm rounded-xl transition-all duration-200 flex items-center justify-center gap-2 shadow-lg shadow-purple-500/20 active:scale-[0.98]"
                >
                  {viewLoading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                  <span>{viewLoading ? '加载中...' : '内容展示'}</span>
                </button>
              )}

              {/* 流程分析摘要卡片 */}
              {result.filter && onViewFlow && (
                <FlowSummaryCard
                  jobId={jobId}
                  filter={result.filter}
                  onViewFlow={() => onViewFlow(result.filter!)}
                />
              )}
            </>
          )}
        </div>
      )}

      {/* Export Button */}
      {!result && (
        <button
          onClick={handleExport}
          disabled={exporting || selectedIMSIs.length === 0 || selectedProtocols.length === 0}
          className="group w-full py-2.5 bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-400 hover:to-blue-500 disabled:from-slate-300 disabled:to-slate-400 disabled:cursor-not-allowed text-white font-bold text-sm rounded-lg transition-all duration-200 flex items-center justify-center gap-2 active:scale-[0.98]"
        >
          {exporting ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-white/90" />
              <span className="tracking-wide">正在解析...</span>
            </>
          ) : (
            <>
              <div className="p-1 bg-white/20 rounded-md group-hover:bg-white/30 transition-colors backdrop-blur-sm">
                <PackageOpen className="w-4 h-4" />
              </div>
              <span className="tracking-wide">开始导出</span>
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
