import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const headers={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
const json=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:{...headers,"Content-Type":"application/json"}});
Deno.serve(async req=>{
  if(req.method==="OPTIONS") return new Response("ok",{headers});
  const token=req.headers.get("Authorization")?.replace(/^Bearer\s+/i,""); if(!token) return json({error:"Authentication required"},401);
  const db=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:"Bearer "+token}}});
  const {data:{user}}=await db.auth.getUser(token); if(!user) return json({error:"Invalid session"},401);
  const {data:profile}=await db.from("profiles").select("organization_id,full_name,role").eq("id",user.id).single(); if(!profile) return json({error:"Profile not provisioned"},403);
  const {prompt=""}=await req.json().catch(()=>({}));
  const [risks,controls,remediations,vulns]=await Promise.all([
    db.from("risks").select("risk_code,title,category,likelihood,impact,residual_likelihood,residual_impact,status,due_date").limit(50),
    db.from("controls").select("control_code,title,status,effectiveness").limit(100),
    db.from("remediations").select("title,priority,status,due_date").limit(50),
    db.from("vulnerabilities").select("cve,cvss,severity,status,due_date").limit(50)
  ]);
  const context={organization_id:profile.organization_id,risks:risks.data||[],controls:controls.data||[],remediations:remediations.data||[],vulnerabilities:vulns.data||[]};
  const endpoint=Deno.env.get("AI_API_URL"), key=Deno.env.get("AI_API_KEY"), model=Deno.env.get("AI_MODEL")||"gpt-4o-mini";
  if(!endpoint||!key) return json({mode:"context-only",answer:"AI provider is not configured. I can still summarize the live GRC context returned by the platform.",context});
  const r=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json","Authorization:"Bearer "+key},body:JSON.stringify({model,messages:[{role:"system",content:"You are CyberTech 360 GRC Copilot. Use only supplied platform records. Do not invent compliance status. Identify assumptions and cite record IDs when available."},{role:"user",content:prompt+"\n\nPLATFORM CONTEXT:\n"+JSON.stringify(context)}]})});
  const data=await r.json(); if(!r.ok) return json({error:data?.error?.message||"AI provider error"},502);
  return json({mode:"ai",answer:data?.choices?.[0]?.message?.content||"No answer returned.",context});
});