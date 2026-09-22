import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const headers={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{...headers,"Content-Type":"application/json"}});
const roles={read:["super_admin","grc_manager","security_manager","risk_manager","compliance_officer","auditor","soc_analyst","it_admin","executive","viewer"],write:["super_admin","grc_manager","security_manager","risk_manager","compliance_officer","it_admin"],admin:["super_admin","it_admin"]};
const tables=new Set(["risks","controls","evidence","remediations","vulnerabilities","pci_scope_items","assessment_items","assessments","incidents","assets","vendors","audits"]);
Deno.serve(async req=>{
  if(req.method==="OPTIONS") return new Response("ok",{headers});
  const token=req.headers.get("Authorization")?.replace(/^Bearer\s+/i,"");
  if(!token) return json({error:"Authentication required"},401);
  const admin=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:"Bearer "+token}}});
  const {data:{user},error:ue}=await admin.auth.getUser(token); if(ue||!user) return json({error:"Invalid session"},401);
  const {data:profile,error:pe}=await admin.from("profiles").select("id,organization_id,full_name,role").eq("id",user.id).single();
  if(pe||!profile) return json({error:"Profile not provisioned"},403);
  const body=await req.json().catch(()=>({})); const action=body.action; const table=body.table;
  if(action==="context") return json({user,profile});
  if(!tables.has(table)) return json({error:"Unsupported table"},400);
  if(!roles.read.includes(profile.role)) return json({error:"Forbidden"},403);
  if(["insert","update","delete"].includes(action) && !roles.write.includes(profile.role)) return json({error:"Write access denied for role"},403);
  let result;
  try {
    if(action==="list"){ let q=admin.from(table).select(body.select||"*"); if(body.filters) for(const [k,v] of Object.entries(body.filters)) q=q.eq(k,v); if(body.limit) q=q.limit(body.limit); const r=await q; result=r; }
    else if(action==="insert") result=await admin.from(table).insert({...body.record,organization_id:profile.organization_id}).select().single();
    else if(action==="update") result=await admin.from(table).update(body.record).eq("id",body.id).select().single();
    else if(action==="delete") result=await admin.from(table).delete().eq("id",body.id);
    else return json({error:"Unsupported action"},400);
  } catch(e){ return json({error:String(e?.message||e)},500); }
  if(result?.error) return json({error:result.error.message},400);
  return json({data:result?.data??null});
});