/**
 * /crl/:caName.crl 路由。
 */
import { Hono } from "hono";

import type { HonoBindings } from "../env";
import { isCaName, resolveCertsOrigin, type CaName } from "../lib/ca-registry";
import { buildCrl } from "../lib/crl";

export const crlRoutes = new Hono<HonoBindings>();

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

  const origin = resolveCertsOrigin(c.env, c.req.url);
  const der = await buildCrl(c.env, origin, caName as CaName);
  return c.body(der, 200, {
    "Content-Type": "application/pkix-crl",
    "Cache-Control": "public, max-age=3600",
    "Content-Disposition": `inline; filename="${caName}ca.crl"`,
  });
});
