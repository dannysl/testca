/**
 * X.509 终端证书签发核心。
 *
 * 使用 @peculiar/x509 构造 v3 证书，所有扩展按照 CAServer.py 的 `use` 字典迁移。
 * 关键产物：
 *   - certPem / privateKeyPem: 终端证书 + 私钥（PKCS#8 PEM）
 *   - serialHex: 20 字节随机序列号（小写 hex）
 *   - publicKeyFingerprint: SPKI DER 的 SHA-256 十六进制指纹（用于 /revoke）
 */
import * as x509 from "@peculiar/x509";

import {
  CA_PROFILES,
  getDistributionUrls,
  fillTemplate,
  loadCaCert,
  loadCaPrivateKey,
  type CaName,
  derToPem,
} from "./ca-registry";
import {
  randUpperAlnum,
  sha256Hex,
  toHex,
} from "./bytes";
import type { Env } from "../env";

export interface IssueParams {
  caName: CaName;
  /** 1..4 -> 2000/2025/2050/2075 起的 25 年段 */
  vaTime: 1 | 2 | 3 | 4;
  inMail: string;
  inCode: string;
  inMain: string;
  inSubs: string;
  inOrgs: string;
  inPart: string;
  inData: string;
  /** 分号分隔的 SAN 列表（DNS / IP） */
  inComs: string;
}

export interface IssueResult {
  caName: CaName;
  serialHex: string;
  subjectCN: string;
  issuerCN: string;
  notBefore: string;
  notAfter: string;
  certPem: string;
  certDer: Uint8Array;
  privateKeyPem: string;
  publicKeyFingerprint: string;
  friendlyName: string;
  issuerCertPem: string;
}

/**
 * 签发一张终端证书。
 */
export async function issueCertificate(
  env: Env,
  origin: string,
  p: IssueParams,
): Promise<IssueResult> {
  const profile = CA_PROFILES[p.caName];
  if (!profile) throw new Error(`Unknown CA: ${p.caName}`);

  // 1. 加载签发者（父 CA）
  const issuerCert = await loadCaCert(p.caName, origin);
  const issuerKey = await loadCaPrivateKey(env, p.caName);

  // 2. 生成订户 RSA 2048 密钥对
  const keyPair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  // 3. 计算 subject CN（与 CAServer.py 一致）
  const suffix = randUpperAlnum(6);
  const caDisplay = p.caName === "uefi" ? "UEFI" : capitalize(p.caName);
  const friendlyName = `Pikachu ${caDisplay} Signer G1-${suffix}`;

  // 4. 有效期
  const startYear = 2000 + 25 * (p.vaTime - 1);
  const endYear = 2000 + 25 * p.vaTime - 1;
  const notBefore = new Date(Date.UTC(startYear, 0, 1, 0, 0, 0));
  const notAfter = new Date(Date.UTC(endYear, 11, 31, 23, 59, 59));

  // 5. 20 字节随机序列号（与 Python 的 randbytes(16).hex 规模相近，更贴近浏览器 CA 惯例用 20）
  const serialBytes = new Uint8Array(16);
  crypto.getRandomValues(serialBytes);
  // 最高位清零确保是正整数
  serialBytes[0] &= 0x7f;
  if (serialBytes[0] === 0) serialBytes[0] = 0x01;
  const serialHex = toHex(serialBytes);

  // 6. 组装 subject DN
  const subjectParts: string[] = [`CN=${escapeDn(friendlyName)}`];
  if (p.inCode) subjectParts.push(`C=${escapeDn(p.inCode)}`);
  if (p.inMain) subjectParts.push(`ST=${escapeDn(p.inMain)}`);
  if (p.inSubs) subjectParts.push(`L=${escapeDn(p.inSubs)}`);
  if (p.inOrgs) subjectParts.push(`O=${escapeDn(p.inOrgs)}`);
  if (p.inPart) subjectParts.push(`OU=${escapeDn(p.inPart)}`);
  if (p.inMail) subjectParts.push(`E=${escapeDn(p.inMail)}`);
  if (p.inData) subjectParts.push(`2.5.4.13=${escapeDn(p.inData)}`);
  const subject = subjectParts.join(", ");
  const issuerName = issuerCert.subject;

  // 7. 构造扩展
  const extensions: x509.Extension[] = [];

  extensions.push(new x509.BasicConstraintsExtension(false, undefined, true));

  extensions.push(
    new x509.KeyUsagesExtension(
      profile.keyUsage.reduce(
        (acc, bit) => acc | (x509.KeyUsageFlags[bit] ?? 0),
        0 as x509.KeyUsageFlags,
      ),
      true,
    ),
  );

  extensions.push(
    new x509.ExtendedKeyUsageExtension(profile.extKeyUsage, true),
  );

  // AKI / SKI
  extensions.push(await x509.SubjectKeyIdentifierExtension.create(keyPair.publicKey));
  extensions.push(
    await x509.AuthorityKeyIdentifierExtension.create(issuerCert, false),
  );

  // SAN：分号分隔
  const sanItems = (p.inComs || "")
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
  if (sanItems.length > 0) {
    const sanNames: x509.JsonGeneralName[] = sanItems.map((v) => {
      // 简单粗暴识别：带 @ -> rfc822Name；IPv4 -> ip；http(s):// -> url；否则 dns
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return { type: "ip", value: v };
      if (/@/.test(v)) return { type: "email", value: v };
      if (/^https?:\/\//i.test(v)) return { type: "url", value: v };
      return { type: "dns", value: v };
    });
    extensions.push(new x509.SubjectAlternativeNameExtension(sanNames));
  }

  // CRL 分发点
  const distUrls = getDistributionUrls(origin);
  extensions.push(
    new x509.Extension(
      "2.5.29.31",
      false,
      encodeCrlDistributionPoints(
        distUrls.crl.map((t) => fillTemplate(t, p.caName)),
      ),
    ),
  );

  // AIA
  extensions.push(
    new x509.AuthorityInfoAccessExtension(
      aiaMap(
        distUrls.aia.map((i) => ({
          method: i.method,
          url: fillTemplate(i.url, p.caName),
        })),
      ),
    ),
  );

  // CertificatePolicies（手工 DER 编码，因为 @peculiar/x509 未导出该扩展类）
  extensions.push(
    new x509.Extension(
      "2.5.29.32",
      false,
      encodeCertificatePolicies(distUrls.policies),
    ),
  );

  // Netscape 扩展（与 CAServer.py 保持一致）
  // nsCertType (2.16.840.1.113730.1.1) - objsign
  extensions.push(
    new x509.Extension(
      "2.16.840.1.113730.1.1",
      false,
      encodeNsCertType(0x10), // objsign = bit 4
    ),
  );

  // nsCaRevocationUrl (2.16.840.1.113730.1.4)
  extensions.push(
    new x509.Extension(
      "2.16.840.1.113730.1.4",
      false,
      encodeIA5StringExtension(
        fillTemplate(`${origin.replace(/\/$/, "")}/certs/??????/??????.crl`, p.caName),
      ),
    ),
  );

  // nsCaPolicyUrl (2.16.840.1.113730.1.8)
  extensions.push(
    new x509.Extension(
      "2.16.840.1.113730.1.8",
      false,
      encodeIA5StringExtension(`${origin.replace(/\/$/, "")}/#/cps`),
    ),
  );

  // 8. 实际签发
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serialHex,
    subject,
    issuer: issuerName,
    notBefore,
    notAfter,
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    publicKey: keyPair.publicKey,
    signingKey: issuerKey,
    extensions,
  });

  // 9. 导出
  const certDer = new Uint8Array(cert.rawData);
  const certPem = cert.toString("pem");

  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyPem = derToPem(pkcs8, "PRIVATE KEY");

  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyFingerprint = await sha256Hex(spki);

  // 父 CA PEM（便于写 chain / PFX）
  const issuerCertPem = issuerCert.toString("pem");

  // subject CN / issuer CN 抽取
  const subjectCN = friendlyName;
  const issuerCN = extractCN(issuerCert.subject) ?? issuerCert.subject;

  return {
    caName: p.caName,
    serialHex,
    subjectCN,
    issuerCN,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    certPem,
    certDer,
    privateKeyPem,
    publicKeyFingerprint,
    friendlyName,
    issuerCertPem,
  };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function capitalize(s: string): string {
  return s.length ? s[0].toUpperCase() + s.slice(1) : s;
}

/** 按 RFC 4514 简单转义 DN 值里的特殊字符 */
function escapeDn(s: string): string {
  return String(s).replace(/([\\"+,;<>=])/g, "\\$1").replace(/^ | $/g, (c) => `\\${c}`);
}

function extractCN(dn: string): string | null {
  const m = dn.match(/CN=([^,]+)/i);
  return m ? m[1].trim() : null;
}

/** peculiar/x509 AuthorityInfoAccessExtension 构造参数 */
function aiaMap(
  items: Array<{ method: "ocsp" | "caIssuers"; url: string }>,
): { ocsp?: string[]; caIssuers?: string[] } {
  const out: { ocsp?: string[]; caIssuers?: string[] } = {};
  for (const it of items) {
    if (it.method === "ocsp") (out.ocsp ??= []).push(it.url);
    else (out.caIssuers ??= []).push(it.url);
  }
  return out;
}

/**
 * 编码 Netscape nsCertType 扩展值（BIT STRING）。
 *
 * nsCertType 是一个 BIT STRING，各位含义：
 *   bit 0: SSL Client
 *   bit 1: SSL Server
 *   bit 2: S/MIME
 *   bit 3: Object Signing (objsign)
 *   bit 4: Reserved
 *   bit 5: SSL CA
 *   bit 6: S/MIME CA
 *   bit 7: Object Signing CA
 *
 * objsign 对应 bit 4（从高位数第 4 位，即 0x10）
 */
function encodeNsCertType(bits: number): ArrayBuffer {
  // BIT STRING: 1 字节 padding bits count + 1 字节实际位
  const unusedBits = 0; // 8 位全部使用
  const bitString = tlv(0x03, new Uint8Array([unusedBits, bits]));
  return (bitString.buffer as ArrayBuffer).slice(
    bitString.byteOffset,
    bitString.byteOffset + bitString.byteLength,
  );
}

/**
 * 编码 IA5String 类型的 Netscape 扩展值（如 nsCaPolicyUrl、nsCaRevocationUrl）。
 */
function encodeIA5StringExtension(value: string): ArrayBuffer {
  const ia5 = tlv(0x16, new TextEncoder().encode(value)); // IA5String
  return (ia5.buffer as ArrayBuffer).slice(
    ia5.byteOffset,
    ia5.byteOffset + ia5.byteLength,
  );
}

/**
 * 手工构造 CRLDistributionPoints 扩展的 DER value。
 *
 * CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
 * DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT DistributionPointName OPTIONAL, ... }
 * DistributionPointName CHOICE { fullName [0] GeneralNames }
 * GeneralName: URI -> [6] IA5String (context, primitive)
 */
function encodeCrlDistributionPoints(urls: string[]): ArrayBuffer {
  // 每个 URL 独立作为一个 DistributionPoint
  const distributionPoints = urls.map((u) => {
    const bytes = new TextEncoder().encode(u);
    const uri = tlv(0x86, bytes); // [6] IMPLICIT IA5String (uniformResourceIdentifier)
    const fullName = tlv(0xa0, uri); // [0] IMPLICIT GeneralNames (fullName)
    const dpName = tlv(0xa0, fullName); // [0] EXPLICIT DistributionPointName
    return tlv(0x30, dpName); // DistributionPoint SEQUENCE
  });
  const outer = tlv(0x30, concat(...distributionPoints)); // CRLDistributionPoints SEQUENCE OF
  return (outer.buffer as ArrayBuffer).slice(outer.byteOffset, outer.byteOffset + outer.byteLength);
}

/**
 * 手工构造 CertificatePolicies 扩展的 DER value。
 *
 * CertificatePolicies ::= SEQUENCE OF PolicyInformation
 * PolicyInformation ::= SEQUENCE {
 *   policyIdentifier   OBJECT IDENTIFIER,
 *   policyQualifiers   SEQUENCE OF PolicyQualifierInfo OPTIONAL
 * }
 * PolicyQualifierInfo ::= SEQUENCE {
 *   policyQualifierId  OBJECT IDENTIFIER (id-qt-cps = 1.3.6.1.5.5.7.2.1),
 *   qualifier          IA5String
 * }
 */
function encodeCertificatePolicies(
  policies: Record<string, string | null>,
): ArrayBuffer {
  const policyInfos = Object.entries(policies).map(([oid, cpsUri]) => {
    const oidDer = tlv(0x06, encodeOid(oid));
    if (cpsUri) {
      // PolicyQualifierInfo: SEQUENCE { id-qt-cps OID, IA5String }
      const cpsOid = tlv(0x06, encodeOid("1.3.6.1.5.5.7.2.1"));
      const cpsStr = tlv(0x16, new TextEncoder().encode(cpsUri)); // IA5String
      const qualifierInfo = tlv(0x30, concat(cpsOid, cpsStr));
      const qualifiers = tlv(0x30, qualifierInfo); // SEQUENCE OF PolicyQualifierInfo
      return tlv(0x30, concat(oidDer, qualifiers)); // PolicyInformation
    }
    return tlv(0x30, oidDer); // PolicyInformation（仅 OID，无 qualifier）
  });
  const outer = tlv(0x30, concat(...policyInfos));
  return (outer.buffer as ArrayBuffer).slice(outer.byteOffset, outer.byteOffset + outer.byteLength);
}

/** 将点分十进制 OID 字符串编码为 DER 内容字节（不含 tag/length） */
function encodeOid(oid: string): Uint8Array {
  const parts = oid.split(".").map(Number);
  const bytes: number[] = [];
  // 前两个组件合并: 40 * first + second
  bytes.push(40 * parts[0] + parts[1]);
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    if (v < 128) {
      bytes.push(v);
    } else {
      const tmp: number[] = [];
      while (v > 0) {
        tmp.unshift(v & 0x7f);
        v >>= 7;
      }
      for (let j = 0; j < tmp.length - 1; j++) tmp[j] |= 0x80;
      bytes.push(...tmp);
    }
  }
  return new Uint8Array(bytes);
}

function tlv(tag: number, payload: Uint8Array): Uint8Array {
  const len = payload.length;
  let lenBytes: number[];
  if (len < 0x80) lenBytes = [len];
  else {
    const tmp: number[] = [];
    let v = len;
    while (v > 0) {
      tmp.unshift(v & 0xff);
      v >>= 8;
    }
    lenBytes = [0x80 | tmp.length, ...tmp];
  }
  const out = new Uint8Array(1 + lenBytes.length + payload.length);
  out[0] = tag;
  out.set(lenBytes, 1);
  out.set(payload, 1 + lenBytes.length);
  return out;
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const n = arrs.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of arrs) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
