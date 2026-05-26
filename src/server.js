/**
 * Cloudflare Workers / SSR entry point.
 * Wraps TanStack Start's server entry with proper error handling.
 */

let serverEntryPromise;

async function getServerEntry() {
  if (!serverEntryPromise) {
    serverEntryPromise = import("@tanstack/react-start/server-entry").then(
      m => m.default ?? m
    );
  }
  return serverEntryPromise;
}

function errorResponse() {
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Error</title>
  <style>
    body { font: 14px monospace; background: #070c18; color: #94a3b8;
           display: grid; place-items: center; min-height: 100vh; }
    .box { text-align: center; }
    h1 { color: #f87171; margin-bottom: 8px; }
    a { color: #4ade80; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Server Error</h1>
    <p>Something went wrong. <a href="/">Try again →</a></p>
  </div>
</body>
</html>`,
    { status: 500, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

export default {
  async fetch(request, env, ctx) {
    try {
      const handler = await getServerEntry();
      return await handler.fetch(request, env, ctx);
    } catch (error) {
      console.error("[SSR Error]", error);
      return errorResponse();
    }
  },
};
