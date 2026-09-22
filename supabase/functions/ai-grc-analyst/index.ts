import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async(req)=>{
 const auth=req.headers.get("Authorization")||""; if(!auth.startsWith("Bearer "))return Response.json({error:"Unauthorized"},{status:401});
 const sb=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:auth}}});
 const {data:{user},error}=await sb.auth.getUser(); if(error||!user)return Response.json({error:"Unauthorized"},{status:401});
 const {data:profile}=await sb.from("profiles").select("organization_id,role").eq("id",user.id).single(); if(!profile)return Response.json({error:"Profile not found"},{status:403});
 const org=profile.organization_id; const [r,c,v,e,rem,m,si]=await Promise.all([
  sb.from("risks").select("id,risk_code,title,status,residual_likelihood,residual_impact").eq("organization_id",org).limit(100),
  sb.from("controls").select("id,control_code,title,status,effectiveness").eq("organization_id",org).limit(200),
  sb.from("vulnerabilities").select("id,cve,cvss,severity,status,due_date").eq("organization_id",org).limit(200),
  sb.from("evidence").select("id,evidence_code,status,control_id,review_date").eq("organization_id",org).limit(200),
  sb.from("remediations").select("id,title,status,due_date,priority").eq("organization_id",org).limit(200),
  sb.from("security_metrics").select("*").eq("organization_id",org).order("calculated_at",{ascending:false}).limit(20),
  sb.from("siem_events").select("id,event_time,severity,event_type,username,message").eq("organization_id",org).order("event_time",{ascending:false}).limit(100)
 ]);
 const context={risks:r.data||[],controls:c.data||[],vulnerabilities:v.data||[],evidence:e.data||[],remediations:rem.data||[],metrics:m.data||[],siem_events:si.data||[]};
 const prompt=(await req.json()).prompt||"Investigate the current GRC posture.";
 const endpoint=Deno.env.get("AI_API_URL"),key=Deno.env.get("AI_API_KEY"),model=Deno.env.get("AI_MODEL")||"gpt-4.1-mini";
 let answer="No external AI provider configured. Deterministic summary: "+JSON.stringify({prompt,open_risks:context.risks.filter((x:any)=>x.status!=="closed").length,critical_vulnerabilities:context.vulnerabilities.filter((x:any)=>Number(x.cvss)>=9&&x.status!=="closed").length,overdue_remediations:context.remediations.filter((x:any)=>x.due_date&&new Date(x.due_date)<new Date()&&x.status!=="closed").length});
 if(endpoint&&key){const rr=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+key},body:JSON.stringify({model,messages:[{role:"system",content:"You are CyberTech 360's GRC analyst. Use only supplied tenant data. Never invent evidence, controls, incidents or compliance status. Separate facts from recommendations and cite record IDs."},{role:"user",content:prompt+"\nTENANT CONTEXT:\n"+JSON.stringify(context)}]})});const j=await rr.json();answer=j.choices?.[0]?.message?.content||answer;}
 return Response.json({answer,grounded:true,organization_id:org});
});