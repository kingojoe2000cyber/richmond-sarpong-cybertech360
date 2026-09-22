import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const H={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
Deno.serve(async req=>{if(req.method==="OPTIONS")return new Response("ok",{headers:H});
const secret=req.headers.get("x-cron-secret"),expected=Deno.env.get("CRON_SECRET");if(!expected||secret!==expected)return new Response(JSON.stringify({error:"Unauthorized"}),{status:401,headers:{...H,"Content-Type":"application/json"}});
const db=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const {data,error}=await db.rpc("create_sla_notifications");if(error)return new Response(JSON.stringify({error:error.message}),{status:500,headers:{...H,"Content-Type":"application/json"}});
return new Response(JSON.stringify({created:data||0,run_at:new Date().toISOString()}),{headers:{...H,"Content-Type":"application/json"}});});