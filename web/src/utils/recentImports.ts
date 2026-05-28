export interface RecentImportFile {
  name: string
  size: number
}

export interface RecentImport {
  id: string
  jobId: string
  displayName?: string
  fileCount: number
  totalSize: number
  files: RecentImportFile[]
  importedAt: number
}

const recentImportsStorageKey = 'uepcap:recent-imports'
const maxRecentImports = 10

export function readRecentImports(): RecentImport[] {
  try {
    const raw = window.localStorage.getItem(recentImportsStorageKey)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .map(normalizeRecentImport)
      .filter((item): item is RecentImport => item !== null)
      .slice(0, maxRecentImports)
  } catch {
    return []
  }
}

export function writeRecentImports(items: RecentImport[]) {
  try {
    window.localStorage.setItem(recentImportsStorageKey, JSON.stringify(items.slice(0, maxRecentImports)))
  } catch {
    // localStorage can be unavailable in private or restricted browser contexts.
  }
}

export function upsertRecentImport(items: RecentImport[], next: RecentImport) {
  return [
    next,
    ...items.filter(item => item.id !== next.id && item.jobId !== next.jobId),
  ].slice(0, maxRecentImports)
}

export function recentImportTitle(item: RecentImport) {
  if (item.displayName && item.displayName.trim() !== '') return item.displayName.trim()
  if (item.files.length === 0) return '未命名抓包'
  if (item.files.length === 1) return item.files[0].name
  return `${item.files[0].name} 等 ${item.files.length} 个文件`
}

export function formatRecentImportTime(value: number) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '时间未知'
  return date.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

function normalizeRecentImport(value: unknown): RecentImport | null {
  if (!value || typeof value !== 'object') return null
  const item = value as Partial<RecentImport>
  if (typeof item.id !== 'string' || typeof item.jobId !== 'string') return null
  if (!Array.isArray(item.files)) return null
  const files = item.files
    .map(file => {
      if (!file || typeof file !== 'object') return null
      const candidate = file as Partial<RecentImportFile>
      if (typeof candidate.name !== 'string') return null
      return {
        name: candidate.name,
        size: typeof candidate.size === 'number' && Number.isFinite(candidate.size) ? candidate.size : 0,
      }
    })
    .filter((file): file is RecentImportFile => file !== null)

  return {
    id: item.id,
    jobId: item.jobId,
    displayName: typeof item.displayName === 'string' && item.displayName.trim() !== '' ? item.displayName.trim() : undefined,
    fileCount: typeof item.fileCount === 'number' && item.fileCount > 0 ? item.fileCount : files.length,
    totalSize: typeof item.totalSize === 'number' && item.totalSize >= 0
      ? item.totalSize
      : files.reduce((sum, file) => sum + file.size, 0),
    files,
    importedAt: typeof item.importedAt === 'number' ? item.importedAt : Date.now(),
  }
}
