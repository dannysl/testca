/**
 * 将签发产物打包为 ZIP：
 *   certificate.crt / private_key.pem / certificate.pfx / certificate.txt / cert_chains.crt
 * 当 caName === "time" 时额外写入 tsa.crt / tsa.key（与原 Python 版本一致）。
 */
import JSZip from "jszip";

import type { CaName } from "./ca-registry";

export interface BundleInput {
  caName: CaName;
  certPem: string;
  privateKeyPem: string;
  pfx: Uint8Array;
  pfxPassword: string;
  subCaPem: string;
  rootCaPem: string;
}

export async function bundleZip(input: BundleInput): Promise<Uint8Array> {
  const zip = new JSZip();

  zip.file("certificate.crt", input.certPem);
  zip.file("private_key.pem", input.privateKeyPem);
  zip.file("certificate.pfx", input.pfx);
  zip.file("certificate.txt", `PFX File Password: ${input.pfxPassword}`);
  zip.file("cert_chains.crt", `${input.subCaPem}\n${input.rootCaPem}`);

  if (input.caName === "time") {
    zip.file("tsa.crt", input.certPem);
    zip.file("tsa.key", input.privateKeyPem);
  }

  const buf = await zip.generateAsync({
    type: "uint8array",
    compression: "DEFLATE",
    compressionOptions: { level: 6 },
  });
  return buf;
}
