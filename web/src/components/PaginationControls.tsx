import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'

interface PaginationControlsProps {
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number) => void
}

export function PaginationControls({ total, page, pageSize, onPageChange }: PaginationControlsProps) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const safePage = clampPage(page, pageCount)
  const start = total === 0 ? 0 : (safePage - 1) * pageSize + 1
  const end = Math.min(total, safePage * pageSize)
  const [jumpPage, setJumpPage] = useState(String(safePage))

  useEffect(() => {
    setJumpPage(String(safePage))
  }, [safePage, pageCount])

  const goToPage = (nextPage: number) => {
    const nextSafePage = clampPage(nextPage, pageCount)
    setJumpPage(String(nextSafePage))
    onPageChange(nextSafePage)
  }

  const handleJump = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const parsedPage = Number.parseInt(jumpPage, 10)
    if (Number.isNaN(parsedPage)) {
      setJumpPage(String(safePage))
      return
    }
    goToPage(parsedPage)
  }

  return (
    <div className="flex flex-col gap-3 border-t border-slate-200 bg-white px-4 py-3 text-sm text-slate-500 md:flex-row md:items-center md:justify-between">
      <span>显示 {start}-{end} / {total}</span>
      <div className="flex flex-wrap items-center justify-end gap-2">
        <button
          type="button"
          onClick={() => goToPage(safePage - 1)}
          disabled={safePage <= 1}
          className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-bold text-slate-600 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
        >
          上一页
        </button>
        <span className="min-w-16 text-center text-xs font-bold text-slate-600">{safePage} / {pageCount}</span>
        <form onSubmit={handleJump} className="flex items-center gap-1">
          <label className="flex items-center gap-1 text-xs font-bold text-slate-500">
            跳至
            <input
              type="number"
              min={1}
              max={pageCount}
              value={jumpPage}
              onChange={event => setJumpPage(event.target.value)}
              onBlur={() => {
                if (jumpPage.trim() === '') setJumpPage(String(safePage))
              }}
              className="h-8 w-16 rounded-lg border border-slate-200 bg-white px-2 text-center text-xs font-bold tabular-nums text-slate-700 outline-none focus:border-slate-400 focus:ring-2 focus:ring-slate-200"
              aria-label="跳转页码"
            />
            页
          </label>
          <button
            type="submit"
            className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-bold text-slate-600 hover:bg-slate-50"
          >
            跳转
          </button>
        </form>
        <button
          type="button"
          onClick={() => goToPage(safePage + 1)}
          disabled={safePage >= pageCount}
          className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-bold text-slate-600 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
        >
          下一页
        </button>
      </div>
    </div>
  )
}

function clampPage(page: number, pageCount: number) {
  return Math.min(Math.max(page, 1), pageCount)
}
