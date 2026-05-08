# pika-ca-worker

基于 **Hono + Cloudflare Workers** 的在线 CA 证书服务，等价于 [../issue/CAServer.py](../issue/CAServer.py) 的 Serverless 迁移版。

> 🆕 **同站部署模式**：同一个 Worker 同时承载前端 SPA（Vite + React）与后端 API。
> 前端经过 `npm run build` 产出到仓库根 `dist/`，Worker 通过 `[assets]` 绑定直接托管；
> API 路由（/cert/、/ocsp、/crl/*、/revoke、/api/*）仍由 Hono 处理，
> 其余请求回退为前端 SPA。无需再部署到 GitHub Pages 或单独域名。

| 能力 | 路由 | 说明 |
| --- | --- | --- |
| 前端 SPA | `/`、`/apply`、`/overview` 等 | 由 Workers Static Assets 托管 |
| 签发证书 | `GET/POST /cert/` | 输出 ZIP（`.crt/.pem/.pfx/chain`），支持 time/uefi/code/auth/file/mail/mtls/sign 八类 CA |
| OCSP (RFC 6960) | `POST /ocsp`、`GET /ocsp/:b64` | 返回 DER 编码 OCSP Response |
| CRL  (RFC 5280) | `GET /crl/<caName>.crl`（也兼容 `<caName>ca.crl`） | 实时聚合 KV 中已吊销项 |
| 基于私钥吊销 | `POST /revoke` | JSON 或 multipart：`{serial, privateKeyPem, reason?}` |
| 健康检查 | `GET /api/health` | 返回 ts 与路由清单 |

---

## 1. 环境依赖

- Node.js ≥ 18
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/) ≥ 3.x

```bash
cd worker
npm install
```

## 2. 创建 KV

```bash
npx wrangler kv:namespace create CERT_KV
npx wrangler kv:namespace create CERT_KV --preview
```

将返回的 `id` 与 `preview_id` 填入 [wrangler.toml](./wrangler.toml) 中的 `[[kv_namespaces]]` 项。

## 3. 配置 Secret

各级 CA 私钥通过 Wrangler Secret 持久化，不会写入代码仓。需要配置的 Secret：

```
ROOT_CA_KEY  TIME_CA_KEY  UEFI_CA_KEY  CODE_CA_KEY
AUTH_CA_KEY  FILE_CA_KEY  MAIL_CA_KEY  MTLS_CA_KEY
SIGN_CA_KEY  OCSP_CA_KEY
```

依次执行（粘贴 PEM 全文）：

```bash
npx wrangler secret put TIME_CA_KEY
npx wrangler secret put UEFI_CA_KEY
# ... 其余同上
npx wrangler secret put OCSP_CA_KEY
```

可选（Cloudflare Turnstile 人机验证）：

```bash
# 未配置时后端会使用 Cloudflare 官方测试 secret 「1x0000000000000000000000000000000AA」及
# 测试 site key「1x00000000000000000000AA」（总是通过，仅供开发/演示）。
# 生产环境请配置自己的 key：
npx wrangler secret put TURNSTILE_SECRET
# 同时在 wrangler.toml 设置 TURNSTILE_SITE_KEY，前端通过 VITE_TURNSTILE_SITE_KEY 同步配置。
```

> 若 `TURNSTILE_SECRET` 未配置，Worker 自动回退到 Cloudflare 测试 secret，方便本地开发。

> CA **证书（公钥）** 不通过 Secret 传递，而是在运行时 `fetch(<CERTS_ORIGIN>/certs/<xxxca>/<xxxca>.der)`。
> 同站部署下 `CERTS_ORIGIN` 留空即可，Worker 会自动使用请求自身的 origin（前端构建产物里已经带了 `/certs/*`）。
> 若要从外部 origin 取公钥（例如 GitHub Pages），设置 `CERTS_ORIGIN=https://pikachuim.github.io/PikaTestCert` 即可。

## 4. 构建前端 & 本地开发（同站模式）

```bash
# 仓库根先构建前端产物到 dist/
cd ..
npm install
npm run build

# 回到 worker/ 启动本地 Worker（Static Assets + API）
cd worker
npm run dev
# => http://localhost:8786
#    - /           -> 前端 SPA
#    - /cert/      -> 在线签发 API
#    - /api/health -> 健康检查
```

> 便捷命令：仓库根执行 `npm run worker:dev` 可一键完成 `build + wrangler dev`；
> 或 `cd worker && npm run dev:all` 等效。

## 5. 一键部署

```bash
# 仓库根一条命令：构建前端 + 部署 Worker（含 Assets）
npm run worker:deploy
```

或显式分步：

```bash
npm run build               # 仓库根：产出 dist/
cd worker && npm run deploy # 推送 Worker + dist/ 至 Cloudflare
```

---

## 接口示例

### 5.1 签发

```bash
curl -OJ "http://localhost:8786/cert/?ca_name=code&va_time=2\
&in_mail=foo@bar.com&in_code=CN&in_main=Beijing&in_subs=Beijing\
&in_orgs=Demo&in_part=R%26D&in_data=test"
# -> 得到 <serial>.zip
```

ZIP 内含：

```
certificate.crt / private_key.pem / certificate.pfx / certificate.txt / cert_chains.crt
# ca_name=time 时额外：tsa.crt, tsa.key
```

### 5.2 OCSP

```bash
# OpenSSL 发起 OCSP 查询
openssl ocsp -issuer codeca.pem -cert cert.crt \
  -url https://<your-worker>/ocsp -resp_text
```

### 5.3 CRL

```bash
curl -OJ https://<your-worker>/crl/codeca.crl
openssl crl -in codeca.crl -inform DER -noout -text
```

### 5.4 吊销

```bash
curl -X POST https://<your-worker>/revoke \
  -H 'Content-Type: application/json' \
  --data-binary @- <<EOF
{
  "serial": "abcdef...",
  "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...",
  "reason": "keyCompromise"
}
EOF
```

校验不通过返回 401 `{done:false,text:"Invalid private key"}`；成功返回 `{done:true, serial, revokedAt}`。

---

## 目录结构

```
worker/
├─ src/
│  ├─ index.ts               # Hono 入口
│  ├─ env.ts                 # 环境变量类型
│  ├─ lib/
│  │  ├─ ca-registry.ts      # CA 元数据 + 公/私钥加载
│  │  ├─ bytes.ts            # 二进制/hex/base64 辅助
│  │  ├─ issuer.ts           # 证书签发核心
│  │  ├─ pfx.ts              # PKCS#12 打包
│  │  ├─ zipper.ts           # ZIP 组装
│  │  ├─ kv.ts               # KV 存储层
│  │  ├─ captcha.ts          # Cloudflare Turnstile 校验
│  │  ├─ ocsp.ts             # OCSP 响应构造
│  │  └─ crl.ts              # CRL 响应构造
│  ├─ routes/
│  │  ├─ cert.ts             # /cert/
│  │  ├─ ocsp.ts             # /ocsp, /ocsp/:b64
│  │  ├─ crl.ts              # /crl/:file
│  │  └─ revoke.ts           # /revoke
│  └─ __tests__/
├─ wrangler.toml
├─ tsconfig.json
└─ package.json
```

---

## 设计摘要

- **私钥**：仅通过 Wrangler Secret 注入 Worker 运行时；`certs/` 目录只存公钥证书（`.der`）。
- **KV Schema**：`cert:<serial>` 存 JSON 主记录；`byca:<ca>:<serial>` 与 `revoked:<ca>:<serial>` 作为二级索引。
- **OCSP 响应者**：独立的 `certs/ocsprs/ocsprs.der` + `OCSP_CA_KEY`，与签发 CA 解耦（RFC 6960 §2.2）。
- **CRL**：`crlNumber = floor(unix_ts)` 单调递增；`thisUpdate=now, nextUpdate=now+1d`；`Cache-Control: public, max-age=3600` 缓解压力。
- **吊销鉴权**：无账号体系，改以"持有私钥即所有者"判定（对私钥派生 SPKI，再比对 KV 中签发时记录的 SHA-256 指纹）。
- **密码学栈**：`WebCrypto` + `@peculiar/x509` + `pkijs`，完全避开 Node.js `crypto`/OpenSSL，满足 Workers/EdgeOne Pages Functions 的运行时限制。

---

## 与原 Python 服务的差异

| 维度 | Python (CAServer.py) | Worker (本项目) |
| --- | --- | --- |
| 运行时 | Flask + OpenSSL/cryptography | Cloudflare Workers + WebCrypto |
| 持久化 | 本地文件 `cache/` `saves/` | Cloudflare KV |
| OCSP/CRL | 未内建（仅静态 crl 文件） | 实时动态生成 |
| 证书吊销 | 未实现 | `POST /revoke`（私钥证明） |
| 前端托管 | 独立静态站点 / GitHub Pages | 与 API 同站，由 Workers Static Assets 托管 |
| 部署 | `python CAServer.py` | `wrangler deploy`（含前端）|
