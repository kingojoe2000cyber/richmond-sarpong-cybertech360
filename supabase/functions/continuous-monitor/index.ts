import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async(req)=>{
 const secret=Deno.env.get("CRON_SECRET"); if(secret && req.headers.get("x-cron-secret")!==secret)return new Response("Unauthorized",{status:401});
 const sb=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
 const {data:orgs,error}=await sb.from("organizations").select("id"); if(error)return Response.json({error:error.message},{status:500});
 const results=[]; for(const o of orgs||[]){const {data,error:e}=await sb.rpc("run_continuous_monitoring");results.push({organization_id:o.id,result:data,error:e?.message||null});}
 return Response.json({service:"CyberTech 360",version:"2.4",processed:results.length,results});
});