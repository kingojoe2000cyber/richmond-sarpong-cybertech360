import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

Deno.serve(async (req) => {
  const auth = req.headers.get("Authorization");
  if (!auth) return new Response(JSON.stringify({error:"Unauthorized"}), {status:401,headers:{"content-type":"application/json"}});

  const client = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: auth } } }
  );
  const { data: { user }, error } = await client.auth.getUser();
  if (error || !user) return new Response(JSON.stringify({error:"Unauthorized"}), {status:401,headers:{"content-type":"application/json"}});
  const { data: profile } = await client.from("profiles").select("id,organization_id,full_name,role").eq("id",user.id).single();
  return new Response(JSON.stringify({user,profile}), {headers:{"content-type":"application/json"}});
});
