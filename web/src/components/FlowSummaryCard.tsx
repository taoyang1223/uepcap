import { useState, useEffect } from 'react'
import { Loader2, GitBranch, Clock, Layers, Tag, Zap, ChevronRight } from 'lucide-react'

interface FlowBrief {
  packet_count: number
  time_range?: {
    start: string
    end: string
    duration_ms: number
    start_relative: string
    end_relative: string
  }
  protocols_present: string[]
  key_params: {
    imsi?: string[]
    supi?: string[]
    ue_ip?: string[]
    teid?: string[]
    seid?: string[]
    qfi?: string[]
    ran_ue_ngap_id?: string[]
    amf_ue_ngap_id?: string[]
  }
}

interface FlowSummaryCardProps {
  jobId: string
  filter: string
  onViewFlow: () => void
}

// 协议颜色映射
const protocolColors: Record<string, string> = {
  ngap: 'bg-blue-100 text-blue-700 border-blue-200',
  'nas-5gs': 'bg-purple-100 text-purple-700 border-purple-200',
  pfcp: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  s1ap: 'bg-orange-100 text-orange-700 border-orange-200',
  gtpv2: 'bg-cyan-100 text-cyan-700 border-cyan-200',
  gtp: 'bg-teal-100 text-teal-700 border-teal-200',
}

// 格式化时长
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)} ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(2)} s`
  const minutes = Math.floor(ms / 60000)
  const seconds = ((ms % 60000) / 1000).toFixed(1)
  return `${minutes}m ${seconds}s`
}

export function FlowSummaryCard({ jobId, filter, onViewFlow }: FlowSummaryCardProps) {
  const [loading, setLoading] = useState(true)
  const [brief, setBrief] = useState<FlowBrief | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function fetchBrief() {
      try {
        setLoading(true)
        setError(null)

        const response = await fetch(`/api/jobs/${jobId}/flow/brief`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filter }),
        })

        const data = await response.json()

        if (cancelled) return

        if (data.success) {
          setBrief(data.data)
        } else {
          setError(data.error || '获取摘要失败')
        }
      } catch (err) {
        if (!cancelled) {
          setError('获取摘要失败: ' + (err as Error).message)
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    fetchBrief()

    return () => {
      cancelled = true
    }
  }, [jobId, filter])

  if (loading) {
    return (
      <div className="mt-4 p-4 bg-gradient-to-br from-violet-50 to-indigo-50 rounded-xl border border-violet-100">
        <div className="flex items-center gap-3">
          <Loader2 className="w-5 h-5 text-violet-500 animate-spin" />
          <span className="text-sm text-violet-600 font-medium">正在分析过滤结果...</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="mt-4 p-4 bg-red-50 rounded-xl border border-red-100">
        <p className="text-sm text-red-600">{error}</p>
      </div>
    )
  }

  if (!brief) return null

  // 收集有值的关键参数
  const keyParamItems: { label: string; values: string[] }[] = []
  if (brief.key_params.imsi?.length) keyParamItems.push({ label: 'IMSI', values: brief.key_params.imsi })
  if (brief.key_params.ue_ip?.length) keyParamItems.push({ label: 'UE IP', values: brief.key_params.ue_ip })
  if (brief.key_params.teid?.length) keyParamItems.push({ label: 'TEID', values: brief.key_params.teid.slice(0, 3) })
  if (brief.key_params.seid?.length) keyParamItems.push({ label: 'SEID', values: brief.key_params.seid.slice(0, 3) })
  if (brief.key_params.qfi?.length) keyParamItems.push({ label: 'QFI', values: brief.key_params.qfi })

  return (
    <div className="mt-4 p-4 bg-gradient-to-br from-violet-50 via-indigo-50 to-purple-50 rounded-xl border border-violet-100 shadow-sm">
      {/* 标题栏 */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-gradient-to-br from-violet-500 to-purple-600 rounded-lg flex items-center justify-center shadow-sm">
            <GitBranch className="w-4 h-4 text-white" />
          </div>
          <h4 className="font-semibold text-slate-800">流程分析摘要</h4>
        </div>
        <button
          onClick={onViewFlow}
          className="group flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-violet-500 to-purple-600 hover:from-violet-600 hover:to-purple-700 text-white font-semibold text-sm rounded-lg transition-all shadow-md shadow-violet-500/20 hover:shadow-violet-500/30 active:scale-[0.98]"
        >
          <Zap className="w-4 h-4" />
          <span>查看流程</span>
          <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
        </button>
      </div>

      {/* 统计信息 */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        {/* 包数 */}
        <div className="bg-white/60 rounded-lg p-3 border border-white/80">
          <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
            <Layers className="w-3 h-3" />
            <span>数据包</span>
          </div>
          <p className="text-lg font-bold text-slate-800">{brief.packet_count}</p>
        </div>

        {/* 时长 */}
        {brief.time_range && (
          <div className="bg-white/60 rounded-lg p-3 border border-white/80">
            <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
              <Clock className="w-3 h-3" />
              <span>时长</span>
            </div>
            <p className="text-lg font-bold text-slate-800">
              {formatDuration(brief.time_range.duration_ms)}
            </p>
          </div>
        )}

        {/* 协议数 */}
        <div className="bg-white/60 rounded-lg p-3 border border-white/80">
          <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
            <Tag className="w-3 h-3" />
            <span>协议</span>
          </div>
          <p className="text-lg font-bold text-slate-800">{brief.protocols_present.length}</p>
        </div>

        {/* 关键参数数 */}
        <div className="bg-white/60 rounded-lg p-3 border border-white/80">
          <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
            <Zap className="w-3 h-3" />
            <span>关键参数</span>
          </div>
          <p className="text-lg font-bold text-slate-800">{keyParamItems.length}</p>
        </div>
      </div>

      {/* 协议标签 */}
      {brief.protocols_present.length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-slate-500 mb-2">涉及协议</p>
          <div className="flex flex-wrap gap-2">
            {brief.protocols_present.map((proto) => (
              <span
                key={proto}
                className={`px-2 py-1 text-xs font-semibold rounded-md border uppercase ${
                  protocolColors[proto] || 'bg-slate-100 text-slate-700 border-slate-200'
                }`}
              >
                {proto}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* 关键参数预览 */}
      {keyParamItems.length > 0 && (
        <div>
          <p className="text-xs text-slate-500 mb-2">关键参数</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {keyParamItems.slice(0, 4).map((item) => (
              <div key={item.label} className="bg-white/60 rounded-lg px-3 py-2 border border-white/80">
                <span className="text-xs text-slate-500">{item.label}:</span>
                <span className="ml-2 text-sm font-mono text-slate-700">
                  {item.values.slice(0, 2).join(', ')}
                  {item.values.length > 2 && ` +${item.values.length - 2}`}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

