/**
 * 轻量版动态 <script> 加载器，带全局缓存，保证同一个 src 只加载一次。
 * 组件卸载时不做清理（脚本仍保留，后续重新挂载同 provider 组件即可复用）。
 */

const loaded = new Map<string, Promise<void>>()

export function loadScript(src: string, opts?: { crossOrigin?: string; async?: boolean; defer?: boolean }): Promise<void> {
  if (typeof window === 'undefined') return Promise.resolve()
  const existing = loaded.get(src)
  if (existing) return existing

  const p = new Promise<void>((resolve, reject) => {
    const el = document.createElement('script')
    el.src = src
    el.async = opts?.async ?? true
    el.defer = opts?.defer ?? false
    if (opts?.crossOrigin) el.crossOrigin = opts.crossOrigin
    el.onload = () => resolve()
    el.onerror = () => {
      loaded.delete(src)
      reject(new Error(`failed to load script: ${src}`))
    }
    document.head.appendChild(el)
  })
  loaded.set(src, p)
  return p
}
