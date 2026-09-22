import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async(req)=>{
 const key=Deno.env.get("SIEM_INGEST_KEY"); if(key && req.headers.get("x-siem-key")!==key)return new Response("Unauthorized",{status:401});
 const body=await req.json(); const org=body.organization_id; if(!org)return Response.json({error:"organization_id required"},{status:400});
 const sb=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
 const events=Array.isArray(body.events)?body.events:[body];
 const rows=events.map((e:any)=>({organization_id:org,source:e.source||"unknown",external_event_id:e.external_event_id||e.id||crypto.randomUUID(),event_time:e.event_time||new Date().toISOString(),severity:e.severity||"info",event_type:e.event_type||"generic",source_ip:e.source_ip||null,username:e.username||null,message:e.message||null,raw_event:e,normalized:e.normalized||{}}));
 const {data,error}=await sb.from("siem_events").upsert(rows,{onConflict:"organization_id,source,external_event_id"}).select("id"); if(error)return Response.json({error:error.message},{status:500});
 return Response.json({accepted:data?.length||0});
});