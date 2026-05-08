/**
 * /revoke 路由：基于私钥证明持有者身份的吊销接口。
 *
 *   POST /revoke
 *     Body: { serial, privateKeyPem, reason? }
 *     或 multipart/form-data
 *
 *   - 解析上传私钥 -> 派生公钥 SPKI -> SHA-256 指纹
 *   - 与 KV 中记录的 publicKeyFingerprint 比对
 *   - 一致则 markRevoked 并返回 {done:true, serial, revokedAt}
 */
import { Hono } from "hono";

import type { HonoBindings } from "../env";
import { getCert, markRevoked, type RevokeReason } from "../lib/kv";
import { importRsaPrivateKeyPem, pemToDer, type CaName } from "../lib/ca-registry";
import { sha256Hex } from "../lib/bytes";
import { purgeCrlCache } from "./crl";

export const revokeRoutes = new Hono<HonoBindings>();

const MAX_BODY = 16 * 1024;

revokeRoutes.post("/", async (c) => {
  const env = c.env;

  // 1. 体大小保护
  const lenHeader = c.req.header("content-length");
  if (lenHeader && Number(lenHeader) > MAX_BODY) {
    return c.json({ done: false, text: "Payload too large" }, 413);
  }

  const ct = c.req.header("content-type") || "";
  let serial = "";
  let privateKeyPem = "";
  let reason: RevokeReason = "unspecified";

  try {
    if (ct.includes("application/json")) {
      const text = await c.req.text();
      if (text.length > MAX_BODY) {
        return c.json({ done: false, text: "Payload too large" }, 413);
      }
      const j = JSON.parse(text);
      serial = String(j.serial || "").trim().toLowerCase();
      privateKeyPem = String(j.privateKeyPem || j.privateKey || "");
      if (j.reason) reason = String(j.reason) as RevokeReason;
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      const text = await c.req.text();
      if (text.length > MAX_BODY) {
        return c.json({ done: false, text: "Payload too large" }, 413);
      }
      const qs = new URLSearchParams(text);
      serial = (qs.get("serial") || "").trim().toLowerCase();
      privateKeyPem = qs.get("privateKeyPem") || qs.get("privateKey") || "";
      if (qs.get("reason")) reason = qs.get("reason") as RevokeReason;
    } else if (ct.includes("multipart/form-data")) {
      const form = await c.req.formData();
      serial = String(form.get("serial") || "").trim().toLowerCase();
      const pkField = form.get("privateKeyPem") ?? form.get("privateKey");
      if (pkField instanceof File) {
        if (pkField.size > MAX_BODY) {
          return c.json({ done: false, text: "Payload too large" }, 413);
        }
        privateKeyPem = await pkField.text();
      } else if (typeof pkField === "string") {
        privateKeyPem = pkField;
      }
      if (form.get("reason")) reason = String(form.get("reason")) as RevokeReason;
    } else {
      return c.json({ done: false, text: "Unsupported content type" }, 415);
    }
  } catch (e) {
    return c.json({ done: false, text: `Parse body failed: ${(e as Error).message}` }, 400);
  }

  if (!serial || !privateKeyPem) {
    return c.json(
      { done: false, text: "Missing serial or privateKeyPem" },
      400,
    );
  }
  if (privateKeyPem.length > MAX_BODY) {
    return c.json({ done: false, text: "Private key too large" }, 413);
  }

  // 2. 读 KV
  const rec = await getCert(env, serial);
  if (!rec) return c.json({ done: false, text: "Cert not found" }, 404);
  if (rec.status === "revoked") {
    return c.json({ done: false, text: "Already revoked" }, 409);
  }

  // 3. 验私钥所有权：从私钥派生公钥 -> SPKI -> SHA-256 指纹
  let uploadedKey: CryptoKey;
  try {
    uploadedKey = await importRsaPrivateKeyPem(privateKeyPem, "SHA-256");
  } catch (e) {
    console.error("[revoke] importKey failed", e);
    return c.json({ done: false, text: "Invalid private key" }, 401);
  }

  let fingerprint: string;
  try {
    const jwk = await crypto.subtle.exportKey("jwk", uploadedKey);
    // 仅取公钥分量，重新 importKey 再导 SPKI
    const pubJwk: JsonWebKey = {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      alg: jwk.alg,
      ext: true,
      key_ops: ["verify"],
    };
    const pub = await crypto.subtle.importKey(
      "jwk",
      pubJwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["verify"],
    );
    const spki = await crypto.subtle.exportKey("spki", pub);
    fingerprint = await sha256Hex(spki);
  } catch (e) {
    console.error("[revoke] derive public failed", e);
    return c.json({ done: false, text: "Invalid private key" }, 401);
  }

  if (fingerprint !== rec.publicKeyFingerprint) {
    return c.json({ done: false, text: "Invalid private key" }, 401);
  }

  // 4. 标记吊销
  const updated = await markRevoked(env, serial, reason);
  if (!updated) {
    return c.json({ done: false, text: "Cert not found" }, 404);
  }

  // 5. 清除对应 CA 的 CRL 缓存，使吊销立即生效
  c.executionCtx.waitUntil(
    purgeCrlCache(c.req.url, updated.caName as CaName),
  );

  return c.json({
    done: true,
    serial: updated.serial,
    caName: updated.caName,
    revokedAt: updated.revokedAt,
    reason: updated.revokeReason,
  });
});
