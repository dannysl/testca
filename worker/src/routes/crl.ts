/**
 * /crl/:caName.crl 路由。
 *
 * 使用 Cloudflare Cache API 缓存生成的 CRL（7 天有效期）。
 * 吊销证书时需调用 purgeCrlCache() 清除对应 CA 的缓存。
 */
import { Hono } from "hono";

import type { HonoBindings } from "../env";
import { isCaName, resolveCertsOrigin, type CaName } from "../lib/ca-registry";
import { buildCrl } from "../lib/crl";

export const crlRoutes = new Hono<HonoBindings>();

/** CRL 缓存有效期：7 天（秒） */
const CRL_CACHE_TTL = 7 * 24 * 3600;

/**
 * 清除指定 CA 的 CRL 缓存。
 * 在吊销证书后调用，使下次请求重新生成 CRL。
 */
export async function purgeCrlCache(requestUrl: string, caName: CaName): Promise<void> {
  const cache = (caches as unknown as { default: Cache }).default;
  const url = new URL(requestUrl);
  // 清除两种可能的 URL 格式
  const keys = [
    `${url.origin}/crl/${caName}ca.crl`,
    `${url.origin}/crl/${caName}.crl`,
  ];
  for (const key of keys) {
    await cache.delete(new Request(key));
  }
}

crlRoutes.get("/:file", async (c) => {
  const file = c.req.param("file");
  const m = file.match(/^([a-z]+)(?:ca)?\.crl$/i);
  if (!m) return c.json({ done: false, text: "Not Found" }, 404);

  // 兼容 `timeca.crl` 与 `time.crl` 两种写法
  let caName = m[1].toLowerCase();
  if (caName.endsWith("ca")) caName = caName.slice(0, -2);

  if (!isCaName(caName)) {
    return c.json({ done: false, text: `Unknown CA: ${caName}` }, 404);
  }

  // 尝试从 Cache API 读取缓存
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(c.req.url);
  const cached = await cache.match(cacheKey);
  if (cached) {
    return cached;
  }

  // 缓存未命中，重新生成 CRL
  const origin = resolveCertsOrigin(c.env, c.req.url);
  const der = await buildCrl(c.env, origin, caName as CaName);

  const response = new Response(der.buffer as ArrayBuffer, {
    status: 200,
    headers: {
      "Content-Type": "application/pkix-crl",
      "Cache-Control": `public, max-age=${CRL_CACHE_TTL}`,
      "Content-Disposition": `inline; filename="${caName}ca.crl"`,
      "X-CRL-Generated": new Date().toISOString(),
    },
  });

  // 写入 Cache API（异步，不阻塞响应）
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()));

  return response;
});
