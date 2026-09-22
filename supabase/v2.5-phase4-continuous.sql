-- CyberTech 360 V2.5 Phase 4
-- Continuous SOC Automation & AI Investigation
-- Run after V2.4.2 and V2.5 Phase 2 audit SQL.

create extension if not exists pgcrypto;

create table if not exists public.soc_correlation_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  enabled boolean not null default true,
  severity_min text not null default 'high',
  event_type text,
  source text,
  fingerprint_window_minutes integer not null default 15,
  suppression_minutes integer not null default 30,
  create_incident_candidate boolean not null default true,
  create_remediation_candidate boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.soc_alerts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  rule_id uuid references public.soc_correlation_rules(id) on delete set null,
  fingerprint text not null,
  title text not null,
  severity text not null,
  status text not null default 'open',
  event_ids uuid[] not null default '{}',
  source text,
  event_type text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  suppressed_until timestamptz,
  incident_id uuid,
  remediation_id uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists uq_soc_alert_fingerprint_active
  on public.soc_alerts(organization_id, fingerprint)
  where status in ('open','investigating','contained');

create table if not exists public.soc_suppressions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  fingerprint text not null,
  reason text not null,
  expires_at timestamptz not null,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_suppressions_lookup
  on public.soc_suppressions(organization_id, fingerprint, expires_at);

create table if not exists public.soc_automation_runs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references public.organizations(id) on delete cascade,
  run_type text not null,
  status text not null default 'running',
  detected_count integer not null default 0,
  correlated_count integer not null default 0,
  suppressed_count integer not null default 0,
  candidate_count integer not null default 0,
  error_message text,
  started_at timestamptz not null default now(),
  finished_at timestamptz
);

create table if not exists public.soc_investigations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  alert_id uuid references public.soc_alerts(id) on delete set null,
  incident_id uuid references public.incidents(id) on delete set null,
  title text not null,
  status text not null default 'open',
  priority text not null default 'high',
  summary text,
  ai_confidence numeric(5,2),
  mitre_techniques text[] not null default '{}',
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.soc_investigation_messages (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.soc_investigations(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  role text not null,
  content text not null,
  source_refs jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_investigation_messages
  on public.soc_investigation_messages(investigation_id, created_at);

create or replace function public.v25_soc_can_read(p_org uuid)
returns boolean
language sql stable security definer set search_path=''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid()
      and p.organization_id = p_org
      and p.role in ('super_admin','grc_manager','security_manager','risk_manager','compliance_officer','auditor','soc_analyst','it_admin','executive','viewer')
  );
$$;

create or replace function public.v25_soc_can_write(p_org uuid)
returns boolean
language sql stable security definer set search_path=''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid()
      and p.organization_id = p_org
      and p.role in ('super_admin','grc_manager','security_manager','risk_manager','compliance_officer','it_admin','soc_analyst')
  );
$$;

alter table public.soc_correlation_rules enable row level security;
alter table public.soc_alerts enable row level security;
alter table public.soc_suppressions enable row level security;
alter table public.soc_automation_runs enable row level security;
alter table public.soc_investigations enable row level security;
alter table public.soc_investigation_messages enable row level security;

drop policy if exists soc_rules_select on public.soc_correlation_rules;
create policy soc_rules_select on public.soc_correlation_rules for select using (public.v25_soc_can_read(organization_id));
drop policy if exists soc_rules_write on public.soc_correlation_rules;
create policy soc_rules_write on public.soc_correlation_rules for all using (public.v25_soc_can_write(organization_id)) with check (public.v25_soc_can_write(organization_id));

drop policy if exists soc_alerts_select on public.soc_alerts;
create policy soc_alerts_select on public.soc_alerts for select using (public.v25_soc_can_read(organization_id));
drop policy if exists soc_alerts_write on public.soc_alerts;
create policy soc_alerts_write on public.soc_alerts for all using (public.v25_soc_can_write(organization_id)) with check (public.v25_soc_can_write(organization_id));

drop policy if exists soc_suppressions_select on public.soc_suppressions;
create policy soc_suppressions_select on public.soc_suppressions for select using (public.v25_soc_can_read(organization_id));
drop policy if exists soc_suppressions_write on public.soc_suppressions;
create policy soc_suppressions_write on public.soc_suppressions for all using (public.v25_soc_can_write(organization_id)) with check (public.v25_soc_can_write(organization_id));

drop policy if exists soc_runs_select on public.soc_automation_runs;
create policy soc_runs_select on public.soc_automation_runs for select using (organization_id is null or public.v25_soc_can_read(organization_id));

drop policy if exists soc_investigations_select on public.soc_investigations;
create policy soc_investigations_select on public.soc_investigations for select using (public.v25_soc_can_read(organization_id));
drop policy if exists soc_investigations_write on public.soc_investigations;
create policy soc_investigations_write on public.soc_investigations for all using (public.v25_soc_can_write(organization_id)) with check (public.v25_soc_can_write(organization_id));

drop policy if exists soc_messages_select on public.soc_investigation_messages;
create policy soc_messages_select on public.soc_investigation_messages for select using (public.v25_soc_can_read(organization_id));
drop policy if exists soc_messages_write on public.soc_investigation_messages;
create policy soc_messages_write on public.soc_investigation_messages for all using (public.v25_soc_can_write(organization_id)) with check (public.v25_soc_can_write(organization_id));

create or replace function public.run_v25_soc_automation(p_org uuid)
returns jsonb
language plpgsql
security definer
set search_path=''
as $$
declare
  run_id uuid := gen_random_uuid();
  e record;
  rule record;
  fingerprint text;
  alert_id uuid;
  detected integer := 0;
  correlated integer := 0;
  suppressed integer := 0;
  candidates integer := 0;
begin
  insert into public.soc_automation_runs(id,organization_id,run_type,status)
  values(run_id,p_org,'continuous_soc','running');

  for e in
    select s.*
    from public.siem_events s
    where s.organization_id=p_org
      and s.event_time >= now() - interval '15 minutes'
      and lower(coalesce(s.severity,'info')) in ('critical','high','medium')
    order by s.event_time desc
    limit 500
  loop
    detected := detected + 1;
    fingerprint := encode(digest(
      lower(coalesce(e.external_event_id,'') || '|' || coalesce(e.source,'') || '|' ||
      coalesce(e.event_type,'') || '|' || regexp_replace(coalesce(e.message,''),'\s+',' ','g')),
      'sha256'),'hex');

    select * into rule
    from public.soc_correlation_rules r
    where r.organization_id=p_org and r.enabled
      and (r.source is null or lower(r.source)=lower(e.source))
      and (r.event_type is null or lower(r.event_type)=lower(e.event_type))
    order by r.created_at
    limit 1;

    if exists (
      select 1 from public.soc_suppressions s
      where s.organization_id=p_org and s.fingerprint=fingerprint and s.expires_at>now()
    ) then
      suppressed := suppressed + 1;
      continue;
    end if;

    select id into alert_id
    from public.soc_alerts a
    where a.organization_id=p_org
      and a.fingerprint=fingerprint
      and a.status in ('open','investigating','contained')
      and a.last_seen_at >= now() - interval '30 minutes'
    limit 1;

    if alert_id is not null then
      correlated := correlated + 1;
      update public.soc_alerts
      set last_seen_at=greatest(last_seen_at,e.event_time),
          event_ids=array_append(event_ids,e.id),
          updated_at=now()
      where id=alert_id;
    else
      insert into public.soc_alerts(
        organization_id,rule_id,fingerprint,title,severity,status,event_ids,source,event_type,first_seen_at,last_seen_at,suppressed_until
      )
      values(
        p_org,rule.id,fingerprint,
        coalesce(e.event_type,'Security event') || ' — ' || coalesce(e.source,'SIEM'),
        coalesce(e.severity,'medium'),'open',array[e.id],e.source,e.event_type,e.event_time,e.event_time,
        now()+make_interval(mins=>coalesce(rule.suppression_minutes,30))
      )
      returning id into alert_id;
      candidates := candidates + 1;
    end if;
  end loop;

  update public.soc_automation_runs
  set status='completed',detected_count=detected,correlated_count=correlated,
      suppressed_count=suppressed,candidate_count=candidates,finished_at=now()
  where id=run_id;

  return jsonb_build_object(
    'run_id',run_id,'detected',detected,'correlated',correlated,
    'suppressed',suppressed,'candidates',candidates
  );
exception when others then
  update public.soc_automation_runs set status='failed',error_message=sqlerrm,finished_at=now() where id=run_id;
  raise;
end;
$$;

revoke all on function public.run_v25_soc_automation(uuid) from public,anon,authenticated;
grant execute on function public.run_v25_soc_automation(uuid) to service_role;

create or replace view public.v25_soc_alert_queue
with (security_invoker=true)
as
select
  a.*,
  case
    when a.severity='critical' then 4
    when a.severity='high' then 3
    when a.severity='medium' then 2
    else 1
  end as severity_rank
from public.soc_alerts a
where a.status not in ('closed','resolved')
order by severity_rank desc,last_seen_at desc;

select 'V2.5 Phase 4 SOC schema ready' as status;
