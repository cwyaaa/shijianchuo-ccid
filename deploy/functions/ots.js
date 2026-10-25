// Cloudflare Pages Functions · OpenTimestamps 锚定 POST /ots
// 与本地网关 /ots 保持相同 JSON 结构；仅使用 Web 标准 API（Workers 兼容，无 Node 依赖）
const CALENDARS = ['https://a.pool.opentimestamps.org/', 'https://b.pool.opentimestamps.org/'];
const CONFIRM_HOURS = 2;
// DetachedTimestampFile: MAGIC(22B) + version(0x01) + OpSHA256 tag(0x08) + digest(32B) + timestamp 树
const MAGIC = new Uint8Array([0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73,
  0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);

function concatBytes(arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
function bytesToB64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(s);
}
function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export async function onRequest(context) {
  const req = context.request;
  if (req.method !== 'POST') return json({ ok: false, error: 'method not allowed' }, 405);
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: 'bad json' }, 400); }
  const sha = String(body.sha256 || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) return json({ ok: false, error: 'sha256 must be 64 hex chars' }, 400);

  try {
    // 与本地网关一致：锚定内容是 SHA-256 哈希文本，提交 digest = SHA256(文本)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sha)));
    let tsBytes = null, used = null, errs = [];
    for (const url of CALENDARS) {
      try {
        const resp = await fetch(url.replace(/\/+$/, '') + '/digest', {
          method: 'POST',
          headers: { 'Accept': 'application/vnd.opentimestamps.v1' },
          body: digest.buffer,
          signal: AbortSignal.timeout(45000)
        });
        if (resp.ok) { tsBytes = new Uint8Array(await resp.arrayBuffer()); used = url; break; }
        errs.push(url + ': http ' + resp.status);
      } catch (e) {
        errs.push(url + ': ' + ((e && e.message) || 'failed'));
      }
    }
    if (!tsBytes) return json({ ok: false, error: 'OTS calendars failed: ' + errs.join('; ') }, 502);

    const dtf = concatBytes([MAGIC, new Uint8Array([0x01, 0x08]), digest, tsBytes]);
    const otsB64 = bytesToB64(dtf);
    const id = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', dtf.buffer))).slice(0, 12);
    const confirmBy = new Date(Date.now() + CONFIRM_HOURS * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19) + '+08:00';
    return json({
      ok: true, id, status: 'pending',
      submitted_at: new Date().toISOString().replace('T', ' ').slice(0, 19) + '+08:00',
      confirm_by: confirmBy, confirm_hours: CONFIRM_HOURS,
      calendar: used, ots_b64: otsB64
    });
  } catch (e) {
    return json({ ok: false, error: 'OTS ' + ((e && e.message) || 'failed') }, 502);
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
