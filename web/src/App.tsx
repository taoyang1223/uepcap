import { useState, useCallback, useEffect, useRef } from 'react'
import { FileUpload } from './components/FileUpload'
import { IMSIList } from './components/IMSIList'
import { ProtocolSelect } from './components/ProtocolSelect'
import { ExportPanel } from './components/ExportPanel'
import { JobInfo } from './components/JobInfo'
import { TimelineViewer } from './components/TimelineViewer'
import { InstallGuide } from './components/InstallGuide'
import { Network, BookOpen } from 'lucide-react'

interface Job {
  id: string
  status: string
  file_count?: number
}

type ViewMode = 'main' | 'timeline' | 'guide'

function App() {
  const [currentJob, setCurrentJob] = useState<Job | null>(null)
  const [imsiList, setImsiList] = useState<string[]>([])
  const [selectedIMSIs, setSelectedIMSIs] = useState<string[]>([])
  const [selectedProtocols, setSelectedProtocols] = useState<string[]>(['ngap', 'pfcp', 's1ap', 'gtpv2', 'gtpu'])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  // 视图模式和时间线数据
  const [viewMode, setViewMode] = useState<ViewMode>('main')
  const [timelinePackets, setTimelinePackets] = useState<any[]>([])

  const handleUploadComplete = useCallback((jobId: string, fileCount: number) => {
    setCurrentJob({ id: jobId, status: 'ready', file_count: fileCount })
    setImsiList([])
    setSelectedIMSIs([])
    setError(null)
  }, [])

  const handleScanIMSIs = useCallback(() => {
    if (!currentJob) return

    setLoading(true)
    setError(null)
    setImsiList([]) // Clear previous results

    // Use SSE for real-time streaming
    const eventSource = new EventSource(`/api/jobs/${currentJob.id}/imsis/stream`)

    eventSource.addEventListener('imsi', (event) => {
      const imsi = JSON.parse(event.data)
      setImsiList(prev => {
        // Avoid duplicates and keep sorted
        if (prev.includes(imsi)) return prev
        const newList = [...prev, imsi]
        return newList.sort()
      })
    })

    eventSource.addEventListener('done', () => {
      eventSource.close()
      setLoading(false)
    })

    eventSource.addEventListener('error', (event) => {
      if (event instanceof MessageEvent) {
        setError('扫描IMSI失败: ' + JSON.parse(event.data))
      }
      eventSource.close()
      setLoading(false)
    })

    eventSource.onerror = () => {
      eventSource.close()
      setLoading(false)
    }
  }, [currentJob])

  const handleReset = useCallback(() => {
    setCurrentJob(null)
    setImsiList([])
    setSelectedIMSIs([])
    setError(null)
    setViewMode('main')
    setTimelinePackets([])
  }, [])

  // 切换到时间线视图
  const handleViewTimeline = useCallback((packets: any[]) => {
    setTimelinePackets(packets)
    setViewMode('timeline')
  }, [])

  // 从时间线返回主视图
  const handleBackFromTimeline = useCallback(() => {
    setViewMode('main')
  }, [])

  // 切换到安装指南视图
  const handleShowGuide = useCallback(() => {
    setViewMode('guide')
  }, [])

  // 从安装指南返回主视图
  const handleBackFromGuide = useCallback(() => {
    setViewMode('main')
  }, [])

  // Auto-trigger IMSI scan when job is ready
  const hasAutoScanned = useRef(false)
  useEffect(() => {
    if (currentJob && !hasAutoScanned.current && !loading && imsiList.length === 0) {
      hasAutoScanned.current = true
      handleScanIMSIs()
    }
    // Reset flag when job changes
    if (!currentJob) {
      hasAutoScanned.current = false
    }
  }, [currentJob, loading, imsiList.length, handleScanIMSIs])

  // 如果是时间线视图，渲染 TimelineViewer
  if (viewMode === 'timeline') {
    return <TimelineViewer packets={timelinePackets} onBack={handleBackFromTimeline} />
  }

  // 如果是安装指南视图，渲染 InstallGuide
  if (viewMode === 'guide') {
    return <InstallGuide onBack={handleBackFromGuide} />
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans selection:bg-indigo-100 selection:text-indigo-900">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-50 bg-opacity-90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-600/20 transform hover:rotate-6 transition-transform duration-300">
              <Network className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">UE PCAP Filter</h1>
              <p className="text-xs text-slate-500 font-medium">IMSI 关联数据包过滤工具</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleShowGuide}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-slate-600 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition-all duration-200"
            >
              <BookOpen className="w-4 h-4" />
              <span>安装部署</span>
            </button>
            {currentJob && (
              <button
                onClick={handleReset}
                className="px-4 py-2 text-sm font-medium text-slate-600 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition-all duration-200"
              >
                新建任务
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-8 p-4 bg-red-50 rounded-xl text-red-700 flex items-center shadow-sm animate-fade-in">
            <span className="bg-red-100 p-1.5 rounded-xl mr-3 flex-shrink-0">
              <svg className="w-4 h-4 text-red-600" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>
            </span>
            <span className="font-medium">{error}</span>
          </div>
        )}

        {!currentJob ? (
          /* Upload Section */
          <div className="max-w-2xl mx-auto mt-12 animate-fade-in-up">
            <div className="text-center mb-10">
              <h2 className="text-3xl font-extrabold text-slate-900 mb-4 tracking-tight">
                上传抓包文件
              </h2>
              <p className="text-lg text-slate-500 max-w-lg mx-auto leading-relaxed">
                支持 .pcap, .pcapng 格式，自动合并并提取 UE 关键信息
              </p>
            </div>
            <FileUpload onUploadComplete={handleUploadComplete} />
          </div>
        ) : (
          /* Job Processing Section */
          <div className="space-y-6 animate-fade-in">
            {/* Row 1: Job Info */}
            <JobInfo job={currentJob} onScanIMSIs={handleScanIMSIs} loading={loading} />
            
            {/* Row 2: IMSI List - Right below Job Info */}
            <div className="transition-all duration-500 ease-in-out">
              {(imsiList.length > 0 || loading) && (
                <IMSIList
                  imsiList={imsiList}
                  selectedIMSIs={selectedIMSIs}
                  onSelectionChange={setSelectedIMSIs}
                />
              )}
            </div>
            
            {/* Row 3: Export Panel & Protocol Select - Side by side */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ExportPanel
                jobId={currentJob.id}
                selectedIMSIs={selectedIMSIs}
                selectedProtocols={selectedProtocols}
                onViewTimeline={handleViewTimeline}
              />
              
              <ProtocolSelect
                selectedProtocols={selectedProtocols}
                onSelectionChange={setSelectedProtocols}
              />
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-200 py-8 bg-white">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <p className="text-sm text-slate-500">
            基于 <span className="font-semibold text-slate-700">tshark</span> 实现 · 支持 NGAP / PFCP / S1AP / GTPv2 / GTP-U 协议
          </p>
        </div>
      </footer>
    </div>
  )
}

export default App
