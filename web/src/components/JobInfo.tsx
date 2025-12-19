import { Loader2, FileText, BadgeCheck, ScanSearch } from 'lucide-react'

interface Job {
  id: string
  status: string
  file_count?: number
}

interface JobInfoProps {
  job: Job
  onScanIMSIs: () => void
  loading: boolean
}

export function JobInfo({ job, onScanIMSIs, loading }: JobInfoProps) {
  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-6 transition-all">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center flex-shrink-0 shadow-lg shadow-emerald-500/20">
           <BadgeCheck className="w-6 h-6 text-white" />
        </div>
        <div>
          <h3 className="text-lg font-bold text-slate-800 flex items-center gap-3">
            文件预处理完成
            <span className="text-xs px-2.5 py-1 bg-emerald-50 text-emerald-700 rounded-full font-bold uppercase tracking-wide">Ready</span>
          </h3>
          <div className="mt-1.5 flex flex-wrap items-center gap-4 text-sm text-slate-500">
             <div className="flex items-center gap-1.5 bg-slate-50/80 px-2.5 py-1 rounded-lg">
                <span className="text-slate-400 text-xs">ID:</span>
                <span className="font-mono text-slate-600 font-medium">{job.id.slice(0, 8)}</span>
             </div>
             {job.file_count && (
               <div className="flex items-center gap-1.5">
                 <FileText className="w-4 h-4 text-slate-400" />
                 <span>{job.file_count} 个文件已合并</span>
               </div>
             )}
          </div>
        </div>
      </div>
        
      <button
        onClick={onScanIMSIs}
        disabled={loading}
        className="flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 disabled:from-slate-300 disabled:to-slate-400 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all shadow-lg shadow-indigo-500/25 hover:shadow-indigo-500/35 active:scale-[0.98] whitespace-nowrap min-w-[140px]"
      >
        {loading ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            正在扫描...
          </>
        ) : (
          <>
            <ScanSearch className="w-4 h-4" />
            开始扫描 IMSI
          </>
        )}
      </button>
    </div>
  )
}
