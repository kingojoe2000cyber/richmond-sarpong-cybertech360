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
    const org = String(body.organization_id || '');
    const investigationId = String(body.investigation_id || '');
    const prompt = String(body.prompt || 'Investigate the current SOC alert queue.');

    if (!org) return json({ error: 'organization_id is required' }, 400);

    const { data: profile, error: profileError } = await ctx.supabase
      .from('profiles')
      .select('id,organization_id,role')
      .eq('id', ctx.userClaims?.sub)
      .single();

    if (profileError || !profile || profile.organization_id !== org) return json({ error: 'Invalid organization context' }, 403);

    const { data: alerts, error: alertError } = await ctx.supabase
      .from('v25_soc_alert_queue')
      .select('id,title,severity,status,source,event_type,first_seen_at,last_seen_at,event_ids')
      .eq('organization_id', org)
      .limit(30);

    if (alertError) return json({ error: alertError.message }, 400);

    const context = JSON.stringify({ alerts: alerts || [], investigationId, prompt });
    const aiKey = Deno.env.get('OPENAI_API_KEY');

    let answer = 'AI provider is not configured. Review the alert queue manually.';
    if (aiKey) {
      const response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + aiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: Deno.env.get('SOC_AI_MODEL') || 'gpt-5',
          input: 'You are a SOC investigation assistant. Use only the supplied tenant records. Do not invent evidence. Separate observed facts, hypotheses, recommended next steps and confidence. Map relevant activity to MITRE ATT&CK technique IDs when evidence supports the mapping. Context: ' + context
        })
      });
      const result = await response.json();
      answer = result.output_text || answer;
    }

    if (investigationId) {
      await ctx.supabase.from('soc_investigation_messages').insert({
        investigation_id: investigationId,
        organization_id: org,
        role: 'assistant',
        content: answer,
        source_refs: alerts || []
      });
      await ctx.supabase.from('soc_investigations').update({
        summary: answer.slice(0, 4000),
        updated_at: new Date().toISOString()
      }).eq('id', investigationId).eq('organization_id', org);
    }

    return json({
      ok: true,
      answer,
      alert_count: alerts?.length || 0,
      provider_configured: Boolean(aiKey)
    });
  })
};
