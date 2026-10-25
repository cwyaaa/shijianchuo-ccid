// Cloudflare Pages Functions · 探活 GET /health
export async function onRequest(context) {
  return json({
    ok: true,
    tsa: 'https://freetsa.org/tsr',
    ots_calendars: ['https://a.pool.opentimestamps.org/', 'https://b.pool.opentimestamps.org/'],
    confirm_hours: 2,
    test_confirm_seconds: 120
  });
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
