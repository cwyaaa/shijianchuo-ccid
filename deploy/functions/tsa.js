// Cloudflare Pages Functions · RFC3161 时间戳 POST /tsa
// 与本地网关 /tsa 保持相同 JSON 结构；仅使用 Web 标准 API（Workers 兼容，无 Node 依赖）
const TSA_URL = 'https://freetsa.org/tsr';
const SHA256_OID_TLV = new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
const NULL_TLV = new Uint8Array([0x05, 0x00]);

/* ---------- 通用字节工具 ---------- */
function concatBytes(arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToB64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(s);
}

/* ---------- 手写 DER 编码 TimeStampReq ---------- */
function derLen(n) {
  if (n < 0x80) return new Uint8Array([n]);
  const b = [];
  while (n > 0) { b.unshift(n & 0xff); n >>= 8; }
  return new Uint8Array([0x80 | b.length, ...b]);
}
function der(tag, body) { return concatBytes([new Uint8Array([tag]), derLen(body.length), body]); }
function derInt(n) {
  if (n < 0x80) return new Uint8Array([0x02, 0x01, n]);
  const b = [];
  let v = n;
  while (v > 0) { b.unshift(v & 0xff); v >>= 8; }
  return concatBytes([new Uint8Array([0x02]), derLen(b.length), new Uint8Array(b)]);
}
function derOctet(bytes) { return concatBytes([new Uint8Array([0x04]), derLen(bytes.length), bytes]); }
function derSeq(parts) { return der(0x30, concatBytes(parts)); }

function buildTsq(sha256hex) {
  const digest = hexToBytes(sha256hex);
  const algo = derSeq([SHA256_OID_TLV, NULL_TLV]);
  const imprint = derSeq([algo, derOctet(digest)]);
  return derSeq([derInt(1), imprint]);
}

/* ---------- 从 TST 中提取 GeneralizedTime ---------- */
function extractGenTime(tst) {
  for (let i = 0; i < tst.length - 2; i++) {
    if (tst[i] === 0x18) {
      const len = tst[i + 1];
      if (len < 128 && i + 2 + len <= tst.length) {
        let s = '';
        for (let j = 0; j < len; j++) s += String.fromCharCode(tst[i + 2 + j]);
        const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z?$/.exec(s);
        if (m) return m[1] + '-' + m[2] + '-' + m[3] + 'T' + m[4] + ':' + m[5] + ':' + m[6] + 'Z';
      }
    }
  }
  return null;
}

export async function onRequest(context) {
  const req = context.request;
  if (req.method !== 'POST') return json({ ok: false, error: 'method not allowed' }, 405);
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: 'bad json' }, 400); }
  const sha = String(body.sha256 || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) return json({ ok: false, error: 'sha256 must be 64 hex chars' }, 400);

  try {
    const tsq = buildTsq(sha);
    const resp = await fetch(TSA_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query', 'Accept': 'application/timestamp-reply' },
      body: tsq.buffer,
      signal: AbortSignal.timeout(30000)
    });
    if (!resp.ok) return json({ ok: false, error: 'TSA http ' + resp.status }, 502);
    const tst = new Uint8Array(await resp.arrayBuffer());   // 完整 TimeStampResp（即标准 .tsr 文件）
    const gen = extractGenTime(tst);
    return json({
      ok: true, tsa: 'freetsa.org (FreeTSA)',
      tst_b64: bytesToB64(tst), tsr_b64: bytesToB64(tst), genTime: gen
    });
  } catch (e) {
    const msg = e && e.name === 'TimeoutError' ? 'TSA timeout' : ('TSA ' + ((e && e.message) || 'failed'));
    return json({ ok: false, error: msg }, 502);
  }
}

function json(o, code) {
  return new Response(JSON.stringify(o), {
    status: code || 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}
