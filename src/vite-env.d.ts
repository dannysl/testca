/// <reference types="vite/client" />

// ---------------------------------------------------------------------------
// Cloudflare Turnstile —— 外部脚本注入到 window.turnstile
// 文档: https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/
// ---------------------------------------------------------------------------
interface TurnstileRenderOptions {
  sitekey: string
  callback?: (token: string) => void
  'expired-callback'?: () => void
  'error-callback'?: () => void
  theme?: 'light' | 'dark' | 'auto'
  size?: 'normal' | 'compact' | 'flexible'
  action?: string
  cData?: string
  language?: string
  [key: string]: unknown
}

interface TurnstileApi {
  render: (
    container: string | HTMLElement,
    options: TurnstileRenderOptions,
  ) => string
  reset: (widgetId?: string) => void
  remove: (widgetId?: string) => void
  getResponse: (widgetId?: string) => string | undefined
  ready?: (cb: () => void) => void
}

interface Window {
  turnstile?: TurnstileApi
}

// ---------------------------------------------------------------------------
// Vite 环境变量类型扩展
// ---------------------------------------------------------------------------
interface ImportMetaEnv {
  /** Cloudflare Turnstile Site Key（公开值）。留空则使用官方测试 key。 */
  readonly VITE_TURNSTILE_SITE_KEY?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
