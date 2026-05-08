/**
 * 人机验证（仅 Cloudflare Turnstile）。
 *
 * - 固定使用 Cloudflare Turnstile：不再支持其它供应商。
 * - 未配置 TURNSTILE_SECRET 时，兜底使用 Cloudflare 官方公开的测试 Secret
 *   （配合前端的测试 Site Key 1x00000000000000000000AA，恒通过）。
 *   仅用于演示 / 本地开发，生产务必通过 `wrangler secret put TURNSTILE_SECRET`
 *   设置真实密钥。
 */
import type { Env } from "../env";

const TURNSTILE_VERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/** Cloudflare 官方公开测试 Secret：对任意响应都返回 success=true。 */
const TURNSTILE_DEMO_SECRET = "1x0000000000000000000000000000000AA";

export type CaptchaResult = { ok: boolean; reason?: string };

/**
 * 校验前端提交的 Turnstile token。
 * @param env       Worker 运行时环境（读取 TURNSTILE_SECRET）
 * @param token     前端 <Turnstile /> 回调得到的 token
 * @param opts.remoteIp  客户端 IP（CF-Connecting-IP）可选
 */
export async function verifyCaptcha(
  env: Env,
  token: string | undefined,
  opts?: { remoteIp?: string },
): Promise<CaptchaResult> {
  const secret =
    env.TURNSTILE_SECRET && env.TURNSTILE_SECRET.trim()
      ? env.TURNSTILE_SECRET.trim()
      : TURNSTILE_DEMO_SECRET;

  if (secret === TURNSTILE_DEMO_SECRET) {
    console.warn(
      "[captcha] TURNSTILE_SECRET not configured, using Cloudflare public test secret (demo only)",
    );
  }

  if (!token) return { ok: false, reason: "missing turnstile token" };

  try {
    const body = new URLSearchParams({ secret, response: token });
    if (opts?.remoteIp) body.append("remoteip", opts.remoteIp);

    const resp = await fetch(TURNSTILE_VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(3000),
    });
    if (!resp.ok) return { ok: false, reason: `verify http ${resp.status}` };

    const json = (await resp.json()) as {
      success?: boolean;
      "error-codes"?: string[];
    };
    if (json.success === true) return { ok: true };
    return {
      ok: false,
      reason: `turnstile rejected: ${
        (json["error-codes"] || []).join(",") || "unknown"
      }`,
    };
  } catch (e) {
    console.error("[captcha][turnstile] verify failed", e);
    return { ok: false, reason: (e as Error).message };
  }
}
