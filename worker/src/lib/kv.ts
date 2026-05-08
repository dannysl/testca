/**
 * KV 存储层：封装证书状态的读写与索引维护。
 *
 * Key 设计：
 *   - cert:<serial_hex>            —— 主记录（CertRecord JSON）
 *   - byca:<caName>:<serial_hex>   —— 按 CA 遍历的索引（value=serial）
 *   - revoked:<caName>:<serial_hex>—— 已吊销索引（value=revokedAt ISO 字符串）
 */
import type { Env } from "../env";
import type { CaName } from "./ca-registry";

export type CertStatus = "good" | "revoked";

/** OCSP/CRL 常用吊销原因码 (RFC 5280 §5.3.1) */
export type RevokeReason =
  | "unspecified"
  | "keyCompromise"
  | "cACompromise"
  | "affiliationChanged"
  | "superseded"
  | "cessationOfOperation"
  | "certificateHold"
  | "removeFromCRL"
  | "privilegeWithdrawn"
  | "aACompromise";

export interface CertRecord {
  serial: string; // hex lower
  caName: CaName;
  subjectCN: string;
  issuerCN: string;
  notBefore: string; // ISO
  notAfter: string; // ISO
  status: CertStatus;
  issuedAt: string;
  certPem: string;
  publicKeyFingerprint: string; // SPKI SHA-256 hex
  revokedAt?: string;
  revokeReason?: RevokeReason;
}

const CERT_TTL_DAYS_AFTER_EXPIRE = 30; // KV 过期保留期

function keyCert(serial: string) {
  return `cert:${serial.toLowerCase()}`;
}
function keyByCa(caName: CaName, serial: string) {
  return `byca:${caName}:${serial.toLowerCase()}`;
}
function keyRevoked(caName: CaName, serial: string) {
  return `revoked:${caName}:${serial.toLowerCase()}`;
}

/**
 * 写入已签发证书的主记录与索引。
 * 失败则向上抛错（由路由层兜底返回 500）。
 */
export async function saveIssued(
  env: Env,
  record: CertRecord,
): Promise<void> {
  const expirationTtl = computeTtlSeconds(record.notAfter);
  const options: KVNamespacePutOptions = {};
  if (expirationTtl !== null && expirationTtl > 60) {
    options.expirationTtl = expirationTtl;
  }

  const encoder = new TextEncoder();

  // 主记录
  await env.CERT_KV.put(
    keyCert(record.serial),
    JSON.stringify(record),
    options,
  );
  // 索引：按 CA
  await env.CERT_KV.put(keyByCa(record.caName, record.serial), record.serial, options);
}

/** 读取主记录 */
export async function getCert(
  env: Env,
  serial: string,
): Promise<CertRecord | null> {
  // 优先用 toLowerCase key 查找（标准路径）
  let raw = await env.CERT_KV.get(keyCert(serial));
  // 兼容手动导入的记录：key 可能保留了原始大小写
  if (!raw && serial !== serial.toLowerCase()) {
    raw = await env.CERT_KV.get(`cert:${serial}`);
  }
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CertRecord;
  } catch (e) {
    console.error("[kv.getCert] invalid JSON", e);
    return null;
  }
}

/**
 * 将证书标记为已吊销。
 * 返回更新后的完整记录。若不存在返回 null。
 */
export async function markRevoked(
  env: Env,
  serial: string,
  reason: RevokeReason = "unspecified",
): Promise<CertRecord | null> {
  const rec = await getCert(env, serial);
  if (!rec) return null;
  if (rec.status === "revoked") return rec;

  const now = new Date();
  rec.status = "revoked";
  rec.revokedAt = now.toISOString();
  rec.revokeReason = reason;

  const expirationTtl = computeTtlSeconds(rec.notAfter);
  const options: KVNamespacePutOptions = {};
  if (expirationTtl !== null && expirationTtl > 60) {
    options.expirationTtl = expirationTtl;
  }

  await env.CERT_KV.put(keyCert(rec.serial), JSON.stringify(rec), options);
  await env.CERT_KV.put(
    keyRevoked(rec.caName, rec.serial),
    JSON.stringify({ revokedAt: rec.revokedAt, reason }),
    options,
  );
  return rec;
}

/** 列出某 CA 全部已吊销项 */
export async function listRevokedByCa(
  env: Env,
  caName: CaName,
): Promise<Array<{ serial: string; revokedAt: string; reason: RevokeReason }>> {
  const prefix = `revoked:${caName}:`;
  const out: Array<{
    serial: string;
    revokedAt: string;
    reason: RevokeReason;
  }> = [];
  let cursor: string | undefined = undefined;
  do {
    const page: KVNamespaceListResult<unknown> = await env.CERT_KV.list({
      prefix,
      cursor,
      limit: 1000,
    });
    for (const k of page.keys) {
      const serial = k.name.slice(prefix.length);
      const val = await env.CERT_KV.get(k.name);
      if (!val) continue;
      try {
        const parsed = JSON.parse(val);
        out.push({
          serial,
          revokedAt: parsed.revokedAt ?? new Date().toISOString(),
          reason: parsed.reason ?? "unspecified",
        });
      } catch {
        out.push({
          serial,
          revokedAt: new Date().toISOString(),
          reason: "unspecified",
        });
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

/**
 * 计算 KV TTL：以 `notAfter` 为基准并在其后保留一段时间。
 * 若 notAfter 比现在还早（异常），返回 null 表示不设置 TTL。
 */
function computeTtlSeconds(notAfterIso: string): number | null {
  const notAfterMs = Date.parse(notAfterIso);
  if (Number.isNaN(notAfterMs)) return null;
  const end = notAfterMs + CERT_TTL_DAYS_AFTER_EXPIRE * 24 * 3600 * 1000;
  const ttl = Math.floor((end - Date.now()) / 1000);
  return ttl > 0 ? ttl : null;
}
