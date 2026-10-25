// Cloudflare Pages Functions · OTS 状态查询 POST /ots_check
// 接收 ots_b64，按 8 字节 attestation 特征串判定 pending / confirmed
const BTC_ATT = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);     // BitcoinBlockHeaderAttestation
const PENDING_ATT = new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]); // PendingAttestation

function indexOfBytes(hay, needle) {
  outer:
  for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

export async function onRequest(context) {
  const req = context.request;
  if (req.method !== 'POST') return json({ ok: false, error: 'method not allowed' }, 405);
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: 'bad json' }, 400); }
  const b64 = String(body.ots_b64 || '').trim();
  if (!b64) return json({ ok: false, error: 'ots_b64 required' }, 400);

  try {
    const raw = atob(b64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    const confirmed = indexOfBytes(buf, BTC_ATT) !== -1;
    const pending = indexOfBytes(buf, PENDING_ATT) !== -1;
    return json({
      ok: true,
      status: confirmed ? 'confirmed' : 'pending',
      confirmed_at: confirmed ? new Date().toISOString().replace('T', ' ').slice(0, 19) + '+08:00' : null,
      note: confirmed ? '已确认：时间戳已锚定至比特币区块链区块头'
                      : (pending ? '待确认：通常在 2 小时内完成链上锚定' : '凭证状态未知，请稍后重试')
    });
  } catch (e) {
    return json({ ok: false, error: 'bad ots data' }, 400);
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
