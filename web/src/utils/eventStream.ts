export interface StreamEvent<T = unknown> {
  event: string
  data: T
}

export async function readEventStream<T = unknown>(response: Response, onEvent: (event: StreamEvent<T>) => void) {
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    throw new Error(text || `HTTP ${response.status}`)
  }
  if (!response.body) {
    throw new Error('浏览器不支持流式响应')
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    let boundary = buffer.indexOf('\n\n')
    while (boundary >= 0) {
      const raw = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      emitEvent(raw, onEvent)
      boundary = buffer.indexOf('\n\n')
    }
  }

  buffer += decoder.decode()
  if (buffer.trim()) {
    emitEvent(buffer, onEvent)
  }
}

function emitEvent<T>(raw: string, onEvent: (event: StreamEvent<T>) => void) {
  let event = 'message'
  const dataLines: string[] = []
  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith('event:')) {
      event = line.slice(6).trim()
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart())
    }
  }
  if (dataLines.length === 0) return
  const payload = dataLines.join('\n')
  let data: T
  try {
    data = JSON.parse(payload) as T
  } catch {
    data = payload as T
  }
  onEvent({ event, data })
}
