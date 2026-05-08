/**
 * Hono 入口：挂载全局中间件、错误处理、所有子路由。
 *
 * 同站部署模式：
 *   - API：/cert/ · /ocsp · /crl/*.crl · /revoke · /api/*
 *   - 其余请求（/, /apply, /assets/*, /certs/*, /docs/* 等）交给
 *     Cloudflare Workers Static Assets 托管（见 wrangler.toml 的 [assets]）
 *     最终找不到时走 SPA 兜底，返回前端 index.html。
 *
 * 路由清单：
 *   GET/POST /cert/           —— 在线签发
 *   GET      /crl/<caName>.crl —— 实时 CRL
 *   POST     /ocsp             —— OCSP 请求
 *   GET      /ocsp/:b64        —— OCSP 请求（Base64URL）
 *   POST     /revoke           —— 基于私钥的吊销
 *   GET      /api/health       —— 健康检查
 */
// reflect-metadata 必须在所有使用 tsyringe 的模块之前导入
// @peculiar/x509 依赖 tsyringe 做依赖注入，需要此 polyfill
import "reflect-metadata";

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";

import type { Env, HonoBindings } from "./env";

import { certRoutes } from "./routes/cert";
import { ocspRoutes } from "./routes/ocsp";
import { crlRoutes } from "./routes/crl";
import { revokeRoutes } from "./routes/revoke";

const app = new Hono<HonoBindings>();

// 全局中间件 ---------------------------------------------------------------
app.use("*", logger());
app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
    exposeHeaders: ["Content-Disposition"],
    maxAge: 600,
  }),
);

// API 健康检查 --------------------------------------------------------------
app.get("/api/health", (c) =>
  c.json({
    done: true,
    service: "pika-ca-worker",
    ts: Date.now(),
    routes: ["/cert/", "/ocsp", "/ocsp/:b64", "/crl/:caName.crl", "/revoke"],
  }),
);

// Captcha 配置接口：前端从此获取 Turnstile Site Key --------------------------
app.get("/api/captcha/config", (c) => {
  const env = c.env as Env;
  const siteKey =
    env.TURNSTILE_SITE_KEY && env.TURNSTILE_SITE_KEY.trim()
      ? env.TURNSTILE_SITE_KEY.trim()
      : "1x00000000000000000000AA"; // 兜底测试 key
  return c.json({
    done: true,
    provider: "cloudflare",
    sitekey: siteKey,
    scriptUrl:
      "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
  });
});

// 子路由 --------------------------------------------------------------------
app.route("/cert", certRoutes);
app.route("/ocsp", ocspRoutes);
app.route("/crl", crlRoutes);
app.route("/revoke", revokeRoutes);

// ---------------------------------------------------------------------------
// 静态资源兜底：交给 Cloudflare Workers Static Assets。
//
// Hono 的 notFound 处理在 Worker 中会在 API 都未命中时触发；
// 此时把原始 Request 交回 env.ASSETS.fetch() 即可。
// 当 SPA 深链接 /apply、/cert 详情页等被刷新时，
// 由 wrangler.toml 的 `[assets] not_found_handling = "single-page-application"`
// 统一回退到 index.html，实现 SPA Router 支持。
// ---------------------------------------------------------------------------
app.notFound(async (c) => {
  const env = c.env as Env;
  if (env?.ASSETS) {
    return env.ASSETS.fetch(c.req.raw);
  }
  return c.json({ done: false, text: "Not Found" }, 404);
});

// 全局错误兜底 -------------------------------------------------------------
app.onError((err, c) => {
  console.error("[onError]", err?.stack || err);
  return c.json(
    { done: false, text: (err as Error)?.message ?? "Internal Error" },
    500,
  );
});

export default app;
