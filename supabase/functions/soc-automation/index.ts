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

    const { data: profile, error: profileError } = await ctx.supabase
      .from('profiles')
      .select('id,organization_id,role')
      .eq('id', ctx.userClaims?.sub)
      .single();

    if (profileError || !profile || profile.organization_id !== org) {
      return json({ error: 'Organization context is invalid' }, 403);
    }

    if (!['super_admin','grc_manager','security_manager','risk_manager','compliance_officer','it_admin','soc_analyst'].includes(profile.role)) {
      return json({ error: 'SOC automation permission denied' }, 403);
    }

    if (action === 'run') {
      const { data, error } = await ctx.supabaseAdmin.rpc('run_v25_soc_automation', { p_org: org });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, result: data });
    }

    return json({ error: 'Unsupported action' }, 400);
  })
};
