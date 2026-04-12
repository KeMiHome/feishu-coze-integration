export async function onRequest({ env }) {
  return new Response(JSON.stringify({
    message: "Hello World!",
    env: {
      cos_bucket: env.TENCENT_COS_BUCKET,
      cos_region: env.TENCENT_COS_REGION
    }
  }, null, 2), {
    headers: { 'Content-Type': 'application/json' }
  });
}
