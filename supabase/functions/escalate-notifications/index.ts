import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async(req)=>{
 const secret=Deno.env.get("CRON_SECRET"); if(secret && req.headers.get("x-cron-secret")!==secret)return new Response("Unauthorized",{status:401});
 const sb=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
 const {data:rows,error}=await sb.from("notification_escalations").select("*").eq("status","pending"); if(error)return Response.json({error:error.message},{status:500});
 let escalated=0; for(const x of rows||[]){if((Date.now()-new Date(x.created_at).getTime())/60000>=x.escalate_after_minutes){await sb.from("notification_escalations").update({status:"escalated",escalated_at:new Date().toISOString()}).eq("id",x.id);await sb.from("notifications").insert({organization_id:x.organization_id,recipient_id:x.recipient_id,notification_type:"escalation",title:"GRC notification escalated",message:"Notification "+x.notification_id+" requires attention.",severity:"critical",entity_type:"notification",entity_id:x.notification_id});escalated++;}}
 return Response.json({escalated});
});