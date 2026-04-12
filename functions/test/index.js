export async function onRequest(context) {
  return new Response(JSON.stringify({
    success: true,
    message: 'Test API works!'
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}