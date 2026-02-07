export async function handler(request) {
  const data = await request.json();
  return new Response(JSON.stringify({ ok: true, data }));
}

