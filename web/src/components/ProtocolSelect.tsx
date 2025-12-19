import { SlidersHorizontal, Check } from 'lucide-react'

interface Protocol {
  id: string
  name: string
  description: string
  category: '5G' | 'LTE' | '通用'
}

const PROTOCOLS: Protocol[] = [
  { id: 'ngap', name: 'NGAP', description: '5G N2 接口', category: '5G' },
  { id: 'pfcp', name: 'PFCP', description: '5G N4 接口', category: '5G' },
  { id: 's1ap', name: 'S1AP', description: 'LTE S1 接口', category: 'LTE' },
  { id: 'gtpv2', name: 'GTPv2-C', description: '控制面隧道', category: '通用' },
  { id: 'gtpu', name: 'GTP-U', description: '用户面隧道', category: '通用' },
]

interface ProtocolSelectProps {
  selectedProtocols: string[]
  onSelectionChange: (protocols: string[]) => void
}

export function ProtocolSelect({ selectedProtocols, onSelectionChange }: ProtocolSelectProps) {
  const toggleProtocol = (id: string) => {
    if (selectedProtocols.includes(id)) {
      onSelectionChange(selectedProtocols.filter(p => p !== id))
    } else {
      onSelectionChange([...selectedProtocols, id])
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case '5G': return 'text-purple-700 bg-purple-50'
      case 'LTE': return 'text-blue-700 bg-blue-50'
      default: return 'text-slate-600 bg-slate-100'
    }
  }

  return (
    <div className="bg-white rounded-2xl shadow-lg shadow-slate-900/5 p-6 transition-all">
      <h3 className="text-lg font-bold text-slate-800 flex items-center gap-3 mb-2">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center shadow-sm">
          <SlidersHorizontal className="w-5 h-5 text-white" />
        </div>
        <span>协议配置</span>
      </h3>

      <p className="text-sm text-slate-500 mb-5 leading-relaxed pl-12">
        选择需要提取的信令协议，支持多选
      </p>

      <div className="space-y-3">
        {PROTOCOLS.map(protocol => {
          const isSelected = selectedProtocols.includes(protocol.id)
          
          return (
            <div
              key={protocol.id}
              onClick={() => toggleProtocol(protocol.id)}
              className={`
                flex items-center gap-3 p-3.5 rounded-xl cursor-pointer transition-all group
                ${isSelected 
                  ? 'bg-indigo-50 shadow-sm' 
                  : 'bg-slate-50/50 hover:bg-indigo-50/50 hover:shadow-sm'
                }
              `}
            >
              <div className={`
                w-5 h-5 rounded-md flex items-center justify-center transition-all duration-200
                ${isSelected ? 'bg-indigo-600 scale-110 shadow-sm' : 'bg-white shadow-sm group-hover:bg-indigo-100'}
              `}>
                {isSelected && <Check className="w-3 h-3 text-white" strokeWidth={3} />}
              </div>
              
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className={`font-bold ${isSelected ? 'text-indigo-900' : 'text-slate-700'}`}>{protocol.name}</span>
                  <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded-md uppercase tracking-wider ${getCategoryColor(protocol.category)}`}>
                    {protocol.category}
                  </span>
                </div>
                <p className={`text-xs ${isSelected ? 'text-indigo-600/80' : 'text-slate-400'}`}>{protocol.description}</p>
              </div>
            </div>
          )
        })}
      </div>

      {selectedProtocols.length === 0 && (
        <p className="mt-4 text-xs text-amber-700 bg-amber-50/80 px-3 py-2.5 rounded-xl flex items-start gap-2 animate-fade-in">
           <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          <span className="leading-5">请至少选择一个协议以进行导出，否则将无法生成有效的数据包。</span>
        </p>
      )}
    </div>
  )
}
