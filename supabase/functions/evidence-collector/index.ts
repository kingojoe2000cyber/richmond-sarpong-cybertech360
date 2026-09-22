import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async(req)=>{
 const secret=Deno.env.get("CRON_SECRET"); if(secret && req.headers.get("x-cron-secret")!==secret)return new Response("Unauthorized",{status:401});
 const sb=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
 const {data:jobs,error}=await sb.from("evidence_collection_jobs").select("*").eq("status","pending").limit(100); if(error)return Response.json({error:error.message},{status:500});
 for(const j of jobs||[])await sb.from("evidence_collection_jobs").update({status:"ready_for_connector",last_run_at:new Date().toISOString(),records_collected:0}).eq("id",j.id);
 return Response.json({service:"evidence-collector",processed:(jobs||[]).length,connector_ready:true});
});