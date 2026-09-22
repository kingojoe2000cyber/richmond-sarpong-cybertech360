/* CyberTech 360 V2.2.3 — persistent browser data layer. Uses Supabase RLS as the tenant boundary. */
window.CT360_DATA = (() => {
  let db = null;
  const tables = {
    risks:"risks", controls:"controls", evidence:"evidence", remediations:"remediations",
    vulnerabilities:"vulnerabilities", pci_scope_items:"pci_scope_items",
    assessment_items:"assessment_items", assessments:"assessments", audit_log:"audit_log",
    profiles:"profiles", organizations:"organizations", frameworks:"frameworks"
  };
  async function init(){ db = await window.CT360_AUTH?.init(); return db; }
  function client(){ if(!db) throw new Error("Supabase is not configured."); return db; }
  async function list(name, options={}) {
    const q=client().from(tables[name]||name).select(options.select||"*").order(options.order||"created_at",{ascending:false});
    if(options.eq) Object.entries(options.eq).forEach(([k,v])=>q.eq(k,v));
    if(options.limit) q.limit(options.limit);
    const {data,error}=await q; if(error) throw error; return data||[];
  }
  async function one(name,id){ const {data,error}=await client().from(tables[name]||name).select("*").eq("id",id).single(); if(error) throw error; return data; }
  async function insert(name,row){ const {data,error}=await client().from(tables[name]||name).insert(row).select().single(); if(error) throw error; return data; }
  async function update(name,id,row){ const {data,error}=await client().from(tables[name]||name).update(row).eq("id",id).select().single(); if(error) throw error; return data; }
  async function remove(name,id){ const {error}=await client().from(tables[name]||name).delete().eq("id",id); if(error) throw error; }
  async function rpc(fn,args={}){ const {data,error}=await client().rpc(fn,args); if(error) throw error; return data; }
  async function uploadEvidence(file,orgId,evidenceId){
    const bytes=await file.arrayBuffer(), hash=await crypto.subtle.digest("SHA-256",bytes);
    const sha=[...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,"0")).join("");
    const safe=file.name.replace(/[^a-zA-Z0-9._-]/g,"_");
    const path=orgId+"/"+evidenceId+"/"+safe;
    const {error}=await client().storage.from("cybertech-evidence").upload(path,file,{upsert:false,contentType:file.type||"application/octet-stream"});
    if(error) throw error;
    return {path,sha256:sha};
  }
  async function signedEvidenceUrl(path,seconds=300){
    const {data,error}=await client().storage.from("cybertech-evidence").createSignedUrl(path,seconds);
    if(error) throw error; return data.signedUrl;
  }
  async function profile(){ const {data,error}=await client().from("profiles").select("id,organization_id,full_name,role").eq("id",(await client().auth.getUser()).data.user.id).single(); if(error) throw error; return data; }
  async function org(){ const p=await profile(); const {data,error}=await client().from("organizations").select("*").eq("id",p.organization_id).single(); if(error) throw error; return data; }
  return {init,client,list,one,insert,update,remove,rpc,uploadEvidence,signedEvidenceUrl,profile,org};
})();