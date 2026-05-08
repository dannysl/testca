/**
 * Captcha 组件（强制 Cloudflare Turnstile）
 *
 * 设计取舍：
 *   - Site Key 获取优先级：
 *       1) 从后端 /api/captcha/config 接口获取（确保前后端密钥对匹配）
 *       2) import.meta.env.VITE_TURNSTILE_SITE_KEY
 *       3) Cloudflare 官方 Testing Site Key: 1x00000000000000000000AA（总是通过）
 *   - Turnstile api.js 使用 ?render=explicit + 动态注入，
 *     script 天然异步，不需要 window.turnstile.ready()。
 *
 * 使用：
 *   const [token, setToken] = useState('')
 *   const ref = useRef<CaptchaHandle>(null)
 *   <Captcha ref={ref} onToken={setToken} />
 *   // 提交失败/完成后调用 ref.current?.reset()
 */
import React, { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { Spin } from 'antd'
import { loadScript } from '../utils/loadScript'

export interface CaptchaHandle {
  /** 重置 widget，同时清空上层 token */
  reset: () => void
}

interface CaptchaProps {
  onToken: (token: string) => void
  /** Turnstile 主题，默认 auto（跟随系统） */
  theme?: 'light' | 'dark' | 'auto'
}

// Cloudflare 官方公开 testing site key（Always passes），用作兜底
const DEMO_SITE_KEY = '1x00000000000000000000AA'
const TURNSTILE_SCRIPT =
  'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

/** 从后端获取 site key，失败则 fallback 到环境变量或测试 key */
async function fetchSiteKey(): Promise<string> {
  try {
    const resp = await fetch('/api/captcha/config')
    if (resp.ok) {
      const json = await resp.json() as { sitekey?: string }
      if (json.sitekey && json.sitekey.trim()) return json.sitekey.trim()
    }
  } catch (e) {
    console.warn('[captcha] failed to fetch /api/captcha/config, using fallback', e)
  }
  // fallback: 环境变量 → 测试 key
  const fromEnv = (import.meta as unknown as { env?: Record<string, string> })
    ?.env?.VITE_TURNSTILE_SITE_KEY
  if (fromEnv && fromEnv.trim()) return fromEnv.trim()
  return DEMO_SITE_KEY
}

const Captcha = forwardRef<CaptchaHandle, CaptchaProps>(function Captcha(
  { onToken, theme = 'auto' },
  ref,
) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const widgetIdRef = useRef<string | null>(null)

  const [ready, setReady] = useState(false)
  const [errMsg, setErrMsg] = useState<string | null>(null)

  useImperativeHandle(ref, () => ({
    reset: () => {
      onToken('')
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.reset(widgetIdRef.current)
        } catch (e) {
          console.warn('[captcha] turnstile.reset failed', e)
        }
      }
    },
  }))

  useEffect(() => {
    let cancelled = false

    ;(async () => {
      try {
        // 先从后端获取正确的 site key
        const sitekey = await fetchSiteKey()
        if (cancelled) return

        await loadScript(TURNSTILE_SCRIPT, { async: true, defer: true })
        if (cancelled) return
        if (!containerRef.current) return
        if (!window.turnstile) throw new Error('turnstile not available')

        const id = window.turnstile.render(containerRef.current, {
          sitekey,
          theme,
          callback: (token: string) => onToken(token),
          'expired-callback': () => onToken(''),
          'error-callback': () => onToken(''),
        })
        widgetIdRef.current = id
        setReady(true)
      } catch (e) {
        console.error('[captcha] mount failed', e)
        setErrMsg((e as Error).message)
      }
    })()

    return () => {
      cancelled = true
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetIdRef.current)
        } catch {
          /* noop */
        }
        widgetIdRef.current = null
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <div ref={containerRef} id="pika-captcha" />
      {!ready && !errMsg && (
        <div style={{ color: 'var(--ink-2)', fontSize: 12 }}>
          <Spin size="small" /> initializing…
        </div>
      )}
      {errMsg && (
        <div style={{ color: '#d4380d', fontSize: 12 }}>Captcha load failed: {errMsg}</div>
      )}
    </div>
  )
})

export default Captcha
