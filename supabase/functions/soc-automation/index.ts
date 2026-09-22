import 'jsr:@supabase/functions-js/edge-runtime.d.ts';
import { withSupabase } from 'npm:@supabase/server@^1';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

export default {
  fetch: withSupabase({ auth: 'user' }, async (req, ctx) => {
    if (req.method !== 'POST') return json({ error: 'POST required' }, 405);

    const body = await req.json().catch(() => ({}));
    const action = String(body.action || 'run');
    const org = String(body.organization_id || '');

    if (!org) return json({ error: 'organization_id is required' }, 400);

    const userId = String(ctx.userClaims?.sub || '');
    if (!userId) return json({ error: 'Authenticated user identity is missing' }, 401);

    // Authorization is checked with the admin client after the user JWT has
    // already been verified by withSupabase. This avoids a false 403 caused
    // by profile RLS while still enforcing the exact user -> tenant -> role
    // relationship before the privileged automation RPC runs.
    const { data: profile, error: profileError } = await ctx.supabaseAdmin
      .from('profiles')
      .select('id,organization_id,role')
      .eq('id', userId)
      .maybeSingle();

    if (profileError) {
      return json({ error: 'Unable to resolve the authenticated CyberTech 360 profile', detail: profileError.message }, 403);
    }

    if (!profile || profile.organization_id !== org) {
      return json({
        error: 'Organization context is invalid',
        detail: 'The signed-in user is not provisioned for the requested CyberTech 360 organization.'
      }, 403);
    }

    if (!['super_admin','grc_manager','security_manager','risk_manager','compliance_officer','it_admin','soc_analyst'].includes(profile.role)) {
      return json({ error: 'SOC automation permission denied', role: profile.role }, 403);
    }

    if (action === 'run') {
      const { data, error } = await ctx.supabaseAdmin.rpc('run_v25_soc_automation', { p_org: org });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, result: data });
    }

    return json({ error: 'Unsupported action' }, 400);
  })
};
