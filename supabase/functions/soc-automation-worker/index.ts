import 'jsr:@supabase/functions-js/edge-runtime.d.ts';
import { withSupabase } from 'npm:@supabase/server@^1';

export default {
  fetch: withSupabase({ auth: 'secret:automation' }, async (_req, ctx) => {
    const { data: orgs, error } = await ctx.supabaseAdmin
      .from('organizations')
      .select('id')
      .limit(500);

    if (error) {
      console.error('SOC worker organization query failed', error);
      return Response.json({ ok: false, error: error.message }, { status: 500 });
    }

    const results = [];
    for (const org of orgs || []) {
      try {
        const { data, error: runError } = await ctx.supabaseAdmin.rpc(
          'run_v25_soc_automation',
          { p_org: org.id }
        );
        const { data: slaData, error: slaError } = await ctx.supabaseAdmin.rpc(
          'run_v25_incident_sla',
          { p_org: org.id }
        );
        results.push({
          organization_id: org.id,
          ok: !runError && !slaError,
          result: data || null,
          incident_sla: slaData || null,
          error: runError?.message || slaError?.message || null
        });
      } catch (e) {
        results.push({
          organization_id: org.id,
          ok: false,
          error: e instanceof Error ? e.message : String(e)
        });
      }
    }

    return Response.json({
      ok: results.every(x => x.ok),
      processed_organizations: results.length,
      results
    });
  })
};
