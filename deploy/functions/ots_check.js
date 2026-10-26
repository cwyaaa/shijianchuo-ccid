// Cloudflare Pages Functions · OTS 状态查询 POST /ots_check
// 接收 ots_b64，按 attestation 特征串判定 pending / confirmed；确认后提取区块高度并查询区块哈希
const BTC_ATT = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);     // BitcoinBlockHeaderAttestation TAG
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

// OTS varuint（LEB128）：7 位一组、最高位为续位，低位组先读
function readVaruint(bytes, pos) {
  let value = 0, shift = 0;
  for (;;) {
    const b = bytes[pos++];
    if (b === undefined) break;
    value += (b & 0x7f) * Math.pow(2, shift);
    if (!(b & 0x80)) break;
    shift += 7;
  }
  return { value, next: pos };
}

async function blockLookup(height) {
  try {
    const resp = await fetch('https://blockstream.info/api/block-height/' + height, { signal: AbortSignal.timeout(8000) });
    if (resp.ok) return (await resp.text()).trim();
  } catch (e) { /* 查询失败返回 null，页面仍可用高度链接 */ }
  return null;
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
    const pos = indexOfBytes(buf, BTC_ATT);
    const confirmed = pos !== -1;
    const pending = indexOfBytes(buf, PENDING_ATT) !== -1;
    let block = null;
    if (confirmed) {
      // attestation = TAG(8B) + varbytes(payload)；varbytes = varuint(长度) + payload，payload 内才是高度 varuint
      const lenPos = pos + BTC_ATT.length;
      const plen = readVaruint(buf, lenPos);
      const height = readVaruint(buf, plen.next);
      const hash = await blockLookup(height.value);
      block = { height: height.value, hash, explorer: 'https://blockstream.info/block-height/' + height.value };
    }
    return json({
      ok: true,
      status: confirmed ? 'confirmed' : 'pending',
      confirmed_at: confirmed ? new Date().toISOString().replace('T', ' ').slice(0, 19) + '+08:00' : null,
      block,
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
