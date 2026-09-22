/* CyberTech 360 V2.2 — optional Supabase Auth integration.
   Configure window.CT360_SUPABASE_URL and window.CT360_SUPABASE_ANON_KEY
   before enabling hosted authentication. The anon key is public; never place
   the service-role key here. */
window.CT360_AUTH = (() => {
  let client = null;
  async function init() {
    if (!window.supabase || !window.CT360_SUPABASE_URL || !window.CT360_SUPABASE_ANON_KEY) return null;
    client = window.supabase.createClient(window.CT360_SUPABASE_URL, window.CT360_SUPABASE_ANON_KEY, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
    });
    return client;
  }
  async function signIn(email,password){ if(!client) throw new Error("Supabase Auth is not configured"); return client.auth.signInWithPassword({email,password}); }
  async function signOut(){ if(client) return client.auth.signOut(); }
  async function session(){ return client ? client.auth.getSession() : {data:{session:null}}; }
  function onChange(fn){ return client?.auth.onAuthStateChange(fn); }
  return {init,signIn,signOut,session,onChange};
})();
