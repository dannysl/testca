/**
 * /cert/ 签发路由：
 *   GET/POST /cert/  -> ZIP (application/zip) 打包的终端证书 / 私钥 / PFX / 链文件
 *
 * 参数：ca_name, va_time, in_mail, in_code, in_main, in_subs, in_orgs,
 *       in_part, in_data, in_coms, captcha?
 */
import { Hono } from "hono";

import type { HonoBindings } from "../env";

import {
  CA_NAMES,
  isCaName,
  loadCaCert,
  resolveCertsOrigin,
} from "../lib/ca-registry";
import { issueCertificate } from "../lib/issuer";
import { buildPfx } from "../lib/pfx";
import { bundleZip } from "../lib/zipper";
import { saveIssued, type CertRecord } from "../lib/kv";
import { verifyCaptcha } from "../lib/captcha";
import { randAscii } from "../lib/bytes";

export const certRoutes = new Hono<HonoBindings>();

// 同时匹配 /cert 和 /cert/（Hono route("/cert", ...) 下 "/" 只匹配不带尾斜杠）
certRoutes.get("/", (c) => handleIssue(c));
certRoutes.get("/*", (c) => handleIssue(c));
certRoutes.post("/", (c) => handleIssue(c));
certRoutes.post("/*", (c) => handleIssue(c));

async function handleIssue(c: any) {
  const env = c.env;

  // 1. 收集参数（query 与 form 都兼容）
  const url = new URL(c.req.url);
  const qs = url.searchParams;
  let form: URLSearchParams | FormData | null = null;
  const method = c.req.method.toUpperCase();
  if (method === "POST") {
    const ct = c.req.header("content-type") || "";
    if (ct.includes("application/json")) {
      const j = await (c.req.json() as Promise<Record<string, any>>).catch(() => ({}));
      form = new URLSearchParams();
      for (const [k, v] of Object.entries(j)) form.append(k, String(v ?? ""));
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      const text = await c.req.text();
      form = new URLSearchParams(text);
    } else if (ct.includes("multipart/form-data")) {
      form = await c.req.formData();
    }
  }
  const pick = (k: string): string => {
    if (form) {
      const v = (form as any).get(k);
      if (v !== null && v !== undefined && String(v) !== "") return String(v);
    }
    return qs.get(k) ?? "";
  };

  // 2. Captcha（可选）
  const captchaResult = await verifyCaptcha(env, pick("captcha") || undefined, {
    remoteIp:
      c.req.header("cf-connecting-ip") ||
      c.req.header("x-forwarded-for") ||
      undefined,
  });
  if (!captchaResult.ok) {
    return c.json(
      { done: false, text: `Captcha Verify Failed: ${captchaResult.reason}` },
      401,
    );
  }

  // 3. 参数整理
  const ca_name = pick("ca_name").trim().toLowerCase();
  const va_time_raw = pick("va_time").trim();
  const va_time = Number.parseInt(va_time_raw, 10);
  const in_mail = pick("in_mail").trim();
  const in_code = pick("in_code").trim();
  const in_main = pick("in_main").trim();
  const in_subs = pick("in_subs").trim();
  const in_orgs = pick("in_orgs").trim();
  const in_part = pick("in_part").trim();
  const in_data = pick("in_data").trim();
  let in_coms = pick("in_coms") || "";
  in_coms = in_coms
    .replace(/,/g, ";")
    .replace(/ /g, ";")
    .replace(/，/g, ";")
    .replace(/；/g, ";");

  // 4. 参数校验（与 CAServer.py 等价）
  if (!isCaName(ca_name)) {
    return c.json(
      { done: false, text: `Error CA Options, valid: ${CA_NAMES.join(",")}` },
      400,
    );
  }
  if (!(va_time >= 1 && va_time <= 4)) {
    return c.json({ done: false, text: "Error Valid Time (1..4)" }, 400);
  }
  if (!in_code || !in_main || !in_subs) {
    return c.json(
      { done: false, text: "无效的国家代码/省份/城市\nInvalid country code/province/city" },
      400,
    );
  }
  if (!in_orgs || !in_part || !in_mail) {
    return c.json(
      { done: false, text: "无效的组织名称/单元/邮件\nInvalid organization name/unit/email" },
      400,
    );
  }

  // 5. 签发
  const origin = resolveCertsOrigin(env, c.req.url);
  const issued = await issueCertificate(env, origin, {
    caName: ca_name,
    vaTime: va_time as 1 | 2 | 3 | 4,
    inMail: in_mail,
    inCode: in_code,
    inMain: in_main,
    inSubs: in_subs,
    inOrgs: in_orgs,
    inPart: in_part,
    inData: in_data,
    inComs: in_coms,
  });

  // 6. 根 CA PEM（写 chain）
  const rootCaCert = await loadCaCert("root", origin);
  const rootCaPem = rootCaCert.toString("pem");

  // 7. PFX
  const pfxPassword = randAscii(16);
  const pfx = await buildPfx({
    certPem: issued.certPem,
    caCertPem: issued.issuerCertPem,
    privateKeyPem: issued.privateKeyPem,
    friendlyName: issued.friendlyName,
    password: pfxPassword,
  });

  // 8. KV 持久化（必须在返回 ZIP 之前完成，失败则不下发，避免"孤儿证书"）
  const record: CertRecord = {
    serial: issued.serialHex,
    caName: issued.caName,
    subjectCN: issued.subjectCN,
    issuerCN: issued.issuerCN,
    notBefore: issued.notBefore,
    notAfter: issued.notAfter,
    status: "good",
    issuedAt: new Date().toISOString(),
    certPem: issued.certPem,
    publicKeyFingerprint: issued.publicKeyFingerprint,
  };
  await saveIssued(env, record);

  // 9. ZIP 打包
  const zip = await bundleZip({
    caName: issued.caName,
    certPem: issued.certPem,
    privateKeyPem: issued.privateKeyPem,
    pfx,
    pfxPassword,
    subCaPem: issued.issuerCertPem,
    rootCaPem,
  });

  return c.body(zip, 200, {
    "Content-Type": "application/zip",
    "Content-Disposition": `attachment; filename="${issued.serialHex}.zip"`,
    "X-Serial": issued.serialHex,
  });
}
