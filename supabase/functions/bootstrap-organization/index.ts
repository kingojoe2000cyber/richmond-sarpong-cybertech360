import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const headers={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
Deno.serve(async req=>{
  if(req.method==="OPTIONS") return new Response("ok",{headers});
  const token=req.headers.get("Authorization")?.replace(/^Bearer\s+/i,""); if(!token) return new Response(JSON.stringify({error:"Authentication required"}),{status:401,headers});
  const db=createClient(Deno.env.get("SUPABASE_URL")!,Deno.env.get("SUPABASE_ANON_KEY")!,{global:{headers:{Authorization:"Bearer "+token}}});
  const {data:{user}}=await db.auth.getUser(token); if(!user) return new Response(JSON.stringify({error:"Invalid session"}),{status:401,headers});
  const {data:existing}=await db.from("profiles").select("organization_id,role").eq("id",user.id).single();
  if(existing?.role!=="super_admin") return new Response(JSON.stringify({error:"Super administrator required"}),{status:403,headers});
  const {name,slug}=await req.json(); if(!name||!slug) return new Response(JSON.stringify({error:"name and slug required"}),{status:400,headers});
  const {data,error}=await db.from("organizations").insert({name,slug}).select().single();
  return new Response(JSON.stringify({data,error}),{status:error?400:200,headers});
});