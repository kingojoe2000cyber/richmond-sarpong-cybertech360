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
    const action = String(body.action || 'run');
    const org = String(body.organization_id || '');
    if (!org) return json({ error: 'organization_id is required' }, 400);

    const { data: profile, error: profileError } = await auth.admin
      .from('profiles')
      .select('id,organization_id,role')
      .eq('id', auth.userId)
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
      const { data, error } = await auth.admin.rpc('run_v25_soc_automation', { p_org: org });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, result: data });
    }

    return json({ error: 'Unsupported action' }, 400);
  }
};