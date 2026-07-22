import { Files } from 'lucide-react'

interface CaptureFileHintProps {
  filename?: string
  sourceFile?: string
  responseFile?: string
}

export function CaptureFileHint({ filename, sourceFile, responseFile }: CaptureFileHintProps) {
  const files = parseCaptureFiles(filename)
  const resolvedSource = sourceFile || (files.length === 1 ? files[0] : '')

  if (resolvedSource) {
    const requestFile = fileBaseName(resolvedSource)
    const response = responseFile ? fileBaseName(responseFile) : ''
    const responseDiffers = response && response !== requestFile

    return (
      <div className="mb-3 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-emerald-900">
        <div className="flex items-start gap-2">
          <Files className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-600" />
          <div className="min-w-0">
            <p className="text-xs font-bold">确定来源文件</p>
            <p className="mt-0.5 text-xs leading-5 text-emerald-700">
              {responseDiffers ? '请求和响应位于不同的原始抓包。' : '该消息或事务位于以下原始抓包。'}
            </p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              <FileBadge label={responseDiffers ? '请求' : undefined} filename={requestFile} />
              {responseDiffers && <FileBadge label="响应" filename={response} />}
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (files.length === 0) return null

  return (
    <div className="mb-3 rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2.5 text-indigo-900">
      <div className="flex items-start gap-2">
        <Files className="mt-0.5 h-4 w-4 flex-shrink-0 text-indigo-500" />
        <div className="min-w-0">
          <p className="text-xs font-bold">正在定位来源文件</p>
          <p className="mt-0.5 text-xs leading-5 text-indigo-700">
            分析完成后将自动显示这条消息所在的确定原始抓包。
          </p>
        </div>
      </div>
    </div>
  )
}

function FileBadge({ label, filename }: { label?: string; filename: string }) {
  return (
    <span title={filename} className="inline-flex max-w-full items-center gap-1.5 rounded-md bg-white px-2 py-1 font-mono text-xs font-semibold text-slate-700 shadow-sm">
      {label && <span className="font-sans text-[10px] font-bold text-emerald-600">{label}</span>}
      <span className="truncate">{filename}</span>
    </span>
  )
}

function parseCaptureFiles(filename?: string): string[] {
  const value = filename?.trim()
  if (!value) return []

  const multiple = value.match(/^\d+\s+files:\s*(.+)$/i)
  const values = multiple ? multiple[1].split(/,\s*/) : [value]

  return values
    .map(file => fileBaseName(file))
    .filter(Boolean)
}

function fileBaseName(file: string): string {
  const value = file.trim()
  return value.split(/[\\/]/).pop() || value
}
