import { useState, useMemo } from 'react'
import { Radar, Search, CheckSquare, Square, Smartphone, Check, Copy, ChevronDown } from 'lucide-react'
import { copyText } from '../utils/clipboard'

interface IMSIListProps {
  imsiList: string[]
  selectedIMSIs: string[]
  onSelectionChange: (imsis: string[]) => void
}

export function IMSIList({ imsiList, selectedIMSIs, onSelectionChange }: IMSIListProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)

  const filteredList = useMemo(() => {
    if (!searchTerm) return imsiList
    return imsiList.filter(imsi => imsi.includes(searchTerm))
  }, [imsiList, searchTerm])

  const toggleIMSI = (imsi: string) => {
    if (selectedIMSIs.includes(imsi)) {
      onSelectionChange(selectedIMSIs.filter(i => i !== imsi))
    } else {
      onSelectionChange([...selectedIMSIs, imsi])
    }
  }

  const toggleAll = () => {
    if (selectedIMSIs.length === filteredList.length) {
      onSelectionChange([])
    } else {
      onSelectionChange([...filteredList])
    }
  }

  const handleCopy = async (e: React.MouseEvent, imsi: string) => {
    e.stopPropagation()
    const copied = await copyText(imsi)
    if (!copied) return
    setCopiedId(imsi)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const formatIMSI = (imsi: string) => {
    // Format as MCC-MNC-MSIN
    if (imsi.length >= 14) {
      const mcc = imsi.slice(0, 3)
      const mnc = imsi.length === 15 ? imsi.slice(3, 5) : imsi.slice(3, 5)
      const msin = imsi.slice(5)
      return { mcc, mnc, msin, full: imsi }
    }
    return { mcc: '', mnc: '', msin: imsi, full: imsi }
  }

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 p-6 transition-all">
      <div className={`flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between ${collapsed ? '' : 'mb-6'}`}>
        <h3 className="text-lg font-bold text-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-sm">
            <Radar className="w-5 h-5 text-white" />
          </div>
          <span>扫描结果</span>
          <span className="text-xs font-semibold text-slate-500 bg-slate-100 px-2.5 py-1 rounded-full">{imsiList.length}</span>
        </h3>
        
        <div className="flex items-center gap-2">
          {selectedIMSIs.length > 0 && (
            <span className="px-3 py-1.5 bg-indigo-50 text-indigo-600 text-sm font-medium rounded-full animate-fade-in">
              已选 {selectedIMSIs.length} 个 UE
            </span>
          )}
          <button
            onClick={() => setCollapsed(value => !value)}
            className="inline-flex items-center justify-center gap-2 px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm font-semibold rounded-lg transition-all active:scale-[0.98]"
          >
            <ChevronDown className={`w-4 h-4 transition-transform ${collapsed ? '' : 'rotate-180'}`} />
            <span>{collapsed ? '展开' : '收起'}</span>
          </button>
        </div>
      </div>

      {!collapsed && (
        <>
      {/* Search & Toolbar */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="搜索 IMSI..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-slate-50/80 rounded-xl text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:bg-white transition-all text-sm"
          />
        </div>
        <button
          onClick={toggleAll}
          className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-slate-600 hover:text-indigo-600 hover:bg-indigo-50 rounded-xl transition-colors"
        >
          {selectedIMSIs.length === filteredList.length && filteredList.length > 0 ? (
            <CheckSquare className="w-4 h-4 text-indigo-600" />
          ) : (
            <Square className="w-4 h-4" />
          )}
          全选
        </button>
      </div>

      {/* List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[500px] overflow-y-auto pr-1 custom-scrollbar pb-2">
        {filteredList.length === 0 ? (
          <div className="col-span-2 text-center py-16 bg-slate-50/50 rounded-xl border-2 border-dashed border-slate-200">
            <div className="w-16 h-16 bg-slate-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <Smartphone className="w-8 h-8 text-slate-300" />
            </div>
            <h4 className="text-slate-900 font-medium mb-1">暂无数据</h4>
            <p className="text-slate-500 text-sm">
              {searchTerm ? '未找到匹配的 IMSI' : '请先进行扫描以获取 IMSI 列表'}
            </p>
          </div>
        ) : (
          filteredList.map(imsi => {
            const formatted = formatIMSI(imsi)
            const isSelected = selectedIMSIs.includes(imsi)
            
            return (
              <div
                key={imsi}
                onClick={() => toggleIMSI(imsi)}
                className={`
                  flex items-center gap-3 p-3.5 rounded-xl cursor-pointer transition-all group relative
                  ${isSelected 
                    ? 'bg-indigo-50 shadow-sm' 
                    : 'bg-slate-50/50 hover:bg-indigo-50/50 hover:shadow-md hover:-translate-y-0.5'
                  }
                `}
              >
                <div className={`
                    w-5 h-5 rounded-md flex items-center justify-center flex-shrink-0 transition-all duration-200
                    ${isSelected ? 'bg-indigo-600 scale-110 shadow-sm' : 'bg-white shadow-sm group-hover:bg-indigo-100'}
                `}>
                    {isSelected && <Check className="w-3 h-3 text-white" strokeWidth={3} />}
                </div>
                
                <div className="flex-1 min-w-0">
                  <p className="font-mono text-sm tracking-wide">
                    <span className="text-slate-400 font-light">{formatted.mcc}</span>
                    <span className="text-slate-300 mx-1">·</span>
                    <span className="text-slate-500">{formatted.mnc}</span>
                    <span className="text-slate-300 mx-1">·</span>
                    <span className={`font-bold ${isSelected ? 'text-indigo-700' : 'text-slate-800'}`}>{formatted.msin}</span>
                  </p>
                </div>

                <button
                  onClick={(e) => handleCopy(e, imsi)}
                  className={`
                    p-1.5 rounded-lg transition-all
                    ${copiedId === imsi 
                      ? 'text-emerald-500 bg-emerald-50' 
                      : 'text-slate-400 hover:text-indigo-600 hover:bg-indigo-100 opacity-0 group-hover:opacity-100'
                    }
                  `}
                  title="复制 IMSI"
                >
                  {copiedId === imsi ? (
                    <Check className="w-4 h-4" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            )
          })
        )}
      </div>
        </>
      )}
    </div>
  )
}
