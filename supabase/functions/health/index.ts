import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

serve(async (req) => {
  const origin = req.headers.get("origin") ?? "*";
  return new Response(JSON.stringify({
    service: "CyberTech 360",
    version: "2.2",
    status: "ok",
    mode: "production-api-foundation"
  }), {
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": origin,
      "access-control-allow-headers": "authorization, x-client-info, apikey, content-type"
    }
  });
});
