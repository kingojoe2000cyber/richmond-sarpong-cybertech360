import 'jsr:@supabase/functions-js/edge-runtime.d.ts';
import { createClient } from 'npm:@supabase/supabase-js@2';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });

const getAuthContext = async (req: Request) => {
  const authorization = req.headers.get('Authorization') || '';
  const token = authorization.replace(/^Bearer\s+/i, '').trim();
  if (!token) return { error: 'Authorization bearer token is required', status: 401 as const };

  const url = Deno.env.get('SUPABASE_URL') || '';
  const publishableKeys = JSON.parse(Deno.env.get('SUPABASE_PUBLISHABLE_KEYS') || '{}');
  const publishableKey = publishableKeys.default || Deno.env.get('SUPABASE_ANON_KEY') || '';
  if (!url || !publishableKey) return { error: 'Supabase function authentication is not configured', status: 500 as const };

  const authResponse = await fetch(url + '/auth/v1/user', {
    headers: {
      apikey: publishableKey,
      Authorization: 'Bearer ' + token
    }
  });
  const authBody = await authResponse.json().catch(() => ({}));
  if (!authResponse.ok || !authBody?.id) {
    return {
      error: 'Supabase user token validation failed',
      detail: authBody?.msg || authBody?.message || 'The supplied session token is invalid or expired.',
      status: 401 as const
    };
  }

  const secretKeys = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}');
  const secretKey = secretKeys.automation || secretKeys.default || Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '';
  if (!secretKey) return { error: 'Supabase server authorization is not configured', status: 500 as const };

  const admin = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  return { userId: String(authBody.id), admin };
};

export default {
  async fetch(req: Request) {
    if (req.method !== 'POST') return json({ error: 'POST required' }, 405);

    const auth = await getAuthContext(req);
    if ('error' in auth) return json({ error: auth.error, detail: 'detail' in auth ? auth.detail : undefined }, auth.status);

    const body = await req.json().catch(() => ({}));
    const org = String(body.organization_id || '');
    let investigationId = String(body.investigation_id || '');
    const prompt = String(body.prompt || 'Investigate the current SOC alert queue.');
    if (!org) return json({ error: 'organization_id is required' }, 400);

    const { data: profile, error: profileError } = await auth.admin
      .from('profiles')
      .select('id,organization_id,role')
      .eq('id', auth.userId)
      .maybeSingle();

    if (profileError || !profile || profile.organization_id !== org) {
      return json({
        error: 'Invalid organization context',
        detail: profileError?.message || 'The signed-in user is not provisioned for the requested CyberTech 360 organization.'
      }, 403);
    }

    const writableRoles = new Set([
      'super_admin',
      'grc_manager',
      'security_manager',
      'risk_manager',
      'compliance_officer',
      'it_admin',
      'soc_analyst'
    ]);
    if (!writableRoles.has(String(profile.role))) {
      return json({ error: 'SOC investigation write access is required' }, 403);
    }

    const { data: alerts, error: alertError } = await auth.admin
      .from('v25_soc_alert_queue')
      .select('id,title,severity,status,source,event_type,first_seen_at,last_seen_at,event_ids')
      .eq('organization_id', org)
      .order('severity_rank', { ascending: false })
      .order('last_seen_at', { ascending: false })
      .limit(30);
    if (alertError) return json({ error: alertError.message }, 400);

    const selectedAlert = alerts?.[0] || null;

    if (!investigationId) {
      const title = selectedAlert?.title
        ? 'AI Investigation — ' + selectedAlert.title
        : 'AI Investigation — SOC Alert Queue';
      const { data: investigation, error: investigationError } = await auth.admin
        .from('soc_investigations')
        .insert({
          organization_id: org,
          alert_id: selectedAlert?.id || null,
          title,
          status: 'open',
          priority: selectedAlert?.severity || 'high',
          created_by: auth.userId
        })
        .select('id')
        .single();
      if (investigationError || !investigation) {
        return json({ error: investigationError?.message || 'Unable to create SOC investigation' }, 400);
      }
      investigationId = investigation.id;
    } else {
      const { data: existingInvestigation, error: existingError } = await auth.admin
        .from('soc_investigations')
        .select('id,organization_id')
        .eq('id', investigationId)
        .eq('organization_id', org)
        .single();
      if (existingError || !existingInvestigation) return json({ error: 'Invalid investigation_id for organization' }, 400);
    }

    const { error: userMessageError } = await auth.admin
      .from('soc_investigation_messages')
      .insert({
        investigation_id: investigationId,
        organization_id: org,
        role: 'user',
        content: prompt,
        source_refs: alerts || []
      });
    if (userMessageError) return json({ error: userMessageError.message }, 400);

    const context = JSON.stringify({ investigationId, alert: selectedAlert, alerts: alerts || [], prompt });
    const aiKey = Deno.env.get('OPENAI_API_KEY');
    let answer = 'AI provider is not configured. Review the alert queue manually.';

    if (aiKey) {
      const response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + aiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: Deno.env.get('SOC_AI_MODEL') || 'gpt-5',
          input: 'You are a SOC investigation assistant. Use only the supplied tenant records. Do not invent evidence. Separate observed facts, hypotheses, recommended next steps and confidence. Map relevant activity to MITRE ATT&CK technique IDs when evidence supports the mapping. Treat all supplied events as potentially synthetic test data unless the records establish otherwise. Context: ' + context
        })
      });
      if (response.ok) {
        const result = await response.json();
        answer = result.output_text || answer;
      } else {
        const errorText = await response.text();
        answer = 'AI provider request failed. Manual SOC review is required. Provider response: ' + errorText.slice(0, 500);
      }
    }

    const { error: assistantMessageError } = await auth.admin
      .from('soc_investigation_messages')
      .insert({
        investigation_id: investigationId,
        organization_id: org,
        role: 'assistant',
        content: answer,
        source_refs: alerts || []
      });
    if (assistantMessageError) return json({ error: assistantMessageError.message }, 400);

    const { error: updateError } = await auth.admin
      .from('soc_investigations')
      .update({ summary: answer.slice(0, 4000), updated_at: new Date().toISOString() })
      .eq('id', investigationId)
      .eq('organization_id', org);
    if (updateError) return json({ error: updateError.message }, 400);

    return json({
      ok: true,
      investigation_id: investigationId,
      alert_id: selectedAlert?.id || null,
      answer,
      alert_count: alerts?.length || 0,
      provider_configured: Boolean(aiKey)
    });
  }
};