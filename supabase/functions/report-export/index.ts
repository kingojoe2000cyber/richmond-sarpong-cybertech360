import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import * as XLSX from "npm:xlsx@0.18.5";
import { PDFDocument, StandardFonts, rgb } from "npm:pdf-lib@1.17.1";
const H={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
const j=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:{...H,"Content-Type":"application/json"}});
Deno.serve(async req=>{
 if(req.method==="OPTIONS")return new Response("ok",{headers:H});
 const token=req.headers.get("Authorization")?.replace(/^Bearer\s+/i,"");if(!token)return j({error:"Authentication required"},401);
 const db=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:"Bearer "+token}}});
 const {data:{user}}=await db.auth.getUser(token);if(!user)return j({error:"Invalid session"},401);
 const {data:p}=await db.from("profiles").select("organization_id,role").eq("id",user.id).single();if(!p)return j({error:"Profile not provisioned"},403);
 if(!["super_admin","grc_manager","compliance_officer","auditor","executive","it_admin"].includes(p.role))return j({error:"Report permission denied"},403);
 const b=await req.json().catch(()=>({})),format=b.format==="xlsx"?"xlsx":"pdf";
 const [c,r,e,v]=await Promise.all([
  db.from("controls").select("control_code,title,status,effectiveness").limit(500),
  db.from("remediations").select("title,priority,status,due_date").limit(500),
  db.from("evidence").select("evidence_code,file_name,status,review_date").limit(500),
  db.from("vendor_risk_summary").select("vendor_code,name,tier,security_score,residual_risk,risk_band").limit(500)]);
 if([c,r,e,v].some(x=>x.error))return j({error:"Unable to build report data"},500);
 if(format==="xlsx"){
  const wb=XLSX.utils.book_new();
  [["Controls",c.data],["Remediations",r.data],["Evidence",e.data],["Vendor Risk",v.data]].forEach(([name,data])=>XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(data||[]),name));
  const bytes=XLSX.write(wb,{type:"array",bookType:"xlsx"});
  return new Response(bytes,{headers:{...H,"Content-Type":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","Content-Disposition":"attachment; filename=cybertech360-compliance-report.xlsx"}});
 }
 const pdf=await PDFDocument.create(),font=await pdf.embedFont(StandardFonts.Helvetica),bold=await pdf.embedFont(StandardFonts.HelveticaBold);
 let page=pdf.addPage([612,792]),y=750;
 const text=(s,size=10,f=font)=>{if(y<55){page=pdf.addPage([612,792]);y=750}page.drawText(String(s).slice(0,105),{x:42,y,size,font:f,color:rgb(0.1,0.1,0.14)});y-=size+7};
 text("CyberTech 360 — Enterprise Compliance Report",18,bold);text("Generated: "+new Date().toISOString(),9);
 text("Controls: "+(c.data||[]).length+" | Evidence: "+(e.data||[]).length+" | Remediations: "+(r.data||[]).length+" | Vendors: "+(v.data||[]).length,10,bold);y-=8;
 text("CONTROL EFFECTIVENESS",12,bold);(c.data||[]).slice(0,80).forEach(x=>text(x.control_code+" — "+x.title+" — "+x.status+" — "+x.effectiveness+"%"));
 text("REMEDIATIONS",12,bold);(r.data||[]).slice(0,80).forEach(x=>text(x.title+" — "+x.priority+" — "+x.status+" — due "+(x.due_date||"n/a")));
 text("EVIDENCE",12,bold);(e.data||[]).slice(0,80).forEach(x=>text(x.evidence_code+" — "+x.file_name+" — "+x.status));
 text("VENDOR RISK",12,bold);(v.data||[]).slice(0,80).forEach(x=>text(x.vendor_code+" — "+x.name+" — "+x.risk_band+" — residual "+x.residual_risk));
 const bytes=await pdf.save();
 return new Response(bytes,{headers:{...H,"Content-Type":"application/pdf","Content-Disposition":"attachment; filename=cybertech360-compliance-report.pdf"}});
});