-- CyberTech 360 V2.5 Phase 6
-- Advanced SOC Analytics, Threat Intelligence & Deterministic Automated Response
-- No external AI dependency. Safe to rerun.

create extension if not exists pgcrypto;

create table if not exists public.soc_threat_indicators (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  indicator_type text not null check (lower(indicator_type) in ('ip','domain','url','hash','email','user','hostname')),
  indicator_value text not null,
  normalized_value text not null,
  threat_level text not null default 'medium' check (lower(threat_level) in ('critical','high','medium','low','info')),
  confidence integer not null default 50 check (confidence between 0 and 100),
  source text not null default 'internal',
  first_seen_at timestamptz,
  last_seen_at timestamptz,
  expires_at timestamptz,
  tags text[] not null default '{}',
  enabled boolean not null default true,
  notes text,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, indicator_type, normalized_value)
);

create index if not exists idx_soc_ti_lookup
  on public.soc_threat_indicators(organization_id, indicator_type, normalized_value, enabled);

create table if not exists public.soc_indicator_matches (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  indicator_id uuid not null references public.soc_threat_indicators(id) on delete cascade,
  event_id uuid references public.siem_events(id) on delete cascade,
  alert_id uuid references public.soc_alerts(id) on delete set null,
  matched_field text not null,
  matched_value text not null,
  confidence integer not null default 50 check (confidence between 0 and 100),
  created_at timestamptz not null default now(),
  unique (organization_id, indicator_id, event_id, matched_field)
);

create index if not exists idx_soc_indicator_matches_org
  on public.soc_indicator_matches(organization_id, created_at desc);

create table if not exists public.soc_detection_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  description text,
  event_type text,
  severity_min text not null default 'high',
  window_minutes integer not null default 15 check (window_minutes between 1 and 1440),
  threshold integer not null default 5 check (threshold between 1 and 100000),
  enabled boolean not null default true,
  action_mode text not null default 'alert_only' check (lower(action_mode) in ('alert_only','queue_response','require_approval')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, name)
);

create table if not exists public.soc_analytics_snapshots (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  snapshot_at timestamptz not null default now(),
  risk_score numeric(6,2) not null default 0,
  exposure_score numeric(6,2) not null default 0,
  threat_score numeric(6,2) not null default 0,
  response_score numeric(6,2) not null default 0,
  open_alerts integer not null default 0,
  open_incidents integer not null default 0,
  overdue_incidents integer not null default 0,
  critical_vulnerabilities integer not null default 0,
  active_indicators integer not null default 0,
  indicator_matches integer not null default 0,
  queued_response_actions integer not null default 0,
  metrics jsonb not null default '{}'::jsonb
);

create index if not exists idx_soc_analytics_org_time
  on public.soc_analytics_snapshots(organization_id, snapshot_at desc);

create table if not exists public.soc_response_actions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  alert_id uuid references public.soc_alerts(id) on delete set null,
  case_id uuid references public.soc_incident_cases(id) on delete set null,
  indicator_id uuid references public.soc_threat_indicators(id) on delete set null,
  action_type text not null check (lower(action_type) in ('isolate_asset','disable_account','block_indicator','collect_evidence','increase_monitoring','escalate_case','create_task')),
  target_type text not null,
  target_value text not null,
  reason text not null,
  status text not null default 'pending_approval' check (lower(status) in ('pending_approval','approved','rejected','executed','failed','cancelled')),
  approval_required boolean not null default true,
  approved_by uuid references public.profiles(id) on delete set null,
  approved_at timestamptz,
  executed_at timestamptz,
  result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_response_actions_queue
  on public.soc_response_actions(organization_id, status, created_at desc);

create table if not exists public.soc_response_action_runs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  action_id uuid not null references public.soc_response_actions(id) on delete cascade,
  run_mode text not null default 'simulation' check (lower(run_mode) in ('simulation','approved_execution')),
  status text not null default 'queued',
  output jsonb not null default '{}'::jsonb,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_response_runs_org
  on public.soc_response_action_runs(organization_id, created_at desc);

create or replace function public.v25_soc_analytics_can_read(p_org uuid)
returns boolean language sql stable security definer set search_path=''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id=(select auth.uid()) and p.organization_id=p_org
      and p.role in ('super_admin','grc_manager','security_manager','risk_manager','compliance_officer','auditor','soc_analyst','it_admin','executive','viewer')
  );
$$;

create or replace function public.v25_soc_analytics_can_write(p_org uuid)
returns boolean language sql stable security definer set search_path=''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id=(select auth.uid()) and p.organization_id=p_org
      and p.role in ('super_admin','grc_manager','security_manager','risk_manager','it_admin','soc_analyst')
  );
$$;

do $$
declare t text;
begin
  foreach t in array array[
    'soc_threat_indicators','soc_indicator_matches','soc_detection_rules',
    'soc_analytics_snapshots','soc_response_actions','soc_response_action_runs'
  ] loop
    execute format('alter table public.%I enable row level security',t);
    execute format('revoke all on table public.%I from anon',t);
    execute format('grant select,insert,update,delete on table public.%I to authenticated',t);
    execute format('grant all on table public.%I to service_role',t);
  end loop;
end $$;

drop policy if exists soc_ti_select on public.soc_threat_indicators;
create policy soc_ti_select on public.soc_threat_indicators for select to authenticated using (public.v25_soc_analytics_can_read(organization_id));
drop policy if exists soc_ti_write on public.soc_threat_indicators;
create policy soc_ti_write on public.soc_threat_indicators for all to authenticated using (public.v25_soc_analytics_can_write(organization_id)) with check (public.v25_soc_analytics_can_write(organization_id));

drop policy if exists soc_tim_select on public.soc_indicator_matches;
create policy soc_tim_select on public.soc_indicator_matches for select to authenticated using (public.v25_soc_analytics_can_read(organization_id));
drop policy if exists soc_tim_write on public.soc_indicator_matches;
create policy soc_tim_write on public.soc_indicator_matches for all to authenticated using (public.v25_soc_analytics_can_write(organization_id)) with check (public.v25_soc_analytics_can_write(organization_id));

drop policy if exists soc_dr_select on public.soc_detection_rules;
create policy soc_dr_select on public.soc_detection_rules for select to authenticated using (public.v25_soc_analytics_can_read(organization_id));
drop policy if exists soc_dr_write on public.soc_detection_rules;
create policy soc_dr_write on public.soc_detection_rules for all to authenticated using (public.v25_soc_analytics_can_write(organization_id)) with check (public.v25_soc_analytics_can_write(organization_id));

drop policy if exists soc_as_select on public.soc_analytics_snapshots;
create policy soc_as_select on public.soc_analytics_snapshots for select to authenticated using (public.v25_soc_analytics_can_read(organization_id));
drop policy if exists soc_as_write on public.soc_analytics_snapshots;
create policy soc_as_write on public.soc_analytics_snapshots for all to authenticated using (public.v25_soc_analytics_can_write(organization_id)) with check (public.v25_soc_analytics_can_write(organization_id));

drop policy if exists soc_ra_select on public.soc_response_actions;
create policy soc_ra_select on public.soc_response_actions for select to authenticated using (public.v25_soc_analytics_can_read(organization_id));
drop policy if exists soc_ra_write on public.soc_response_actions;
create policy soc_ra_write on public.soc_response_actions for all to authenticated using (public.v25_soc_analytics_can_write(organization_id)) with check (public.v25_soc_analytics_can_write(organization_id));

drop policy if exists soc_rar_select on public.soc_response_action_runs;
create policy soc_rar_select on public.soc_response_action_runs for select to authenticated using (public.v25_soc_analytics_can_read(organization_id));
drop policy if exists soc_rar_write on public.soc_response_action_runs;
create policy soc_rar_write on public.soc_response_action_runs for all to authenticated using (public.v25_soc_analytics_can_write(organization_id)) with check (public.v25_soc_analytics_can_write(organization_id));

insert into public.soc_detection_rules(organization_id,name,description,event_type,severity_min,window_minutes,threshold,action_mode)
select o.id,x.name,x.description,x.event_type,x.severity_min,x.window_minutes,x.threshold,x.action_mode
from public.organizations o
cross join (values
  ('Brute-force burst','Repeated authentication failures in a short window','authentication_failure_burst','high',15,5,'require_approval'),
  ('Critical event response','Critical security telemetry requires a response queue','critical_event', 'critical',10,1,'require_approval'),
  ('High severity event burst','Multiple high-severity events from a source','*','high',10,3,'queue_response')
) x(name,description,event_type,severity_min,window_minutes,threshold,action_mode)
where not exists(select 1 from public.soc_detection_rules r where r.organization_id=o.id and r.name=x.name);

create or replace function public.run_v25_soc_indicator_match(p_org uuid)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare i record; e record; matched integer:=0;
begin
  for i in select * from public.soc_threat_indicators where organization_id=p_org and enabled=true and (expires_at is null or expires_at>now()) loop
    for e in
      select * from public.siem_events
      where organization_id=p_org and event_time > now()-interval '24 hours'
      and (
        lower(coalesce(source_ip,''))=lower(i.normalized_value)
        or lower(coalesce(username,''))=lower(i.normalized_value)
        or lower(coalesce(message,'')) like '%'||lower(i.normalized_value)||'%'
        or lower(coalesce(raw_event::text,'')) like '%'||lower(i.normalized_value)||'%'
      )
      order by event_time desc limit 100
    loop
      insert into public.soc_indicator_matches(organization_id,indicator_id,event_id,matched_field,matched_value,confidence)
      values(p_org,i.id,e.id,
        case when lower(coalesce(e.source_ip,''))=lower(i.normalized_value) then 'source_ip'
             when lower(coalesce(e.username,''))=lower(i.normalized_value) then 'username'
             else 'message_or_raw_event' end,
        i.normalized_value,i.confidence)
      on conflict do nothing;
      if found then matched:=matched+1; end if;
    end loop;
  end loop;
  return jsonb_build_object('organization_id',p_org,'matches_created',matched);
end;
$$;

revoke all on function public.run_v25_soc_indicator_match(uuid) from public,anon,authenticated;
grant execute on function public.run_v25_soc_indicator_match(uuid) to service_role;

create or replace function public.run_v25_soc_analytics(p_org uuid)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare
  oa integer; oi integer; od integer; cv integer; ai integer; im integer; qr integer;
  threat numeric; exposure numeric; response numeric; risk numeric;
  sid uuid;
begin
  select count(*) into oa from public.soc_alerts where organization_id=p_org and lower(status) not in ('closed','resolved');
  select count(*) into oi from public.soc_incident_cases where organization_id=p_org and lower(status) not in ('closed','recovered');
  select count(*) into od from public.soc_incident_cases where organization_id=p_org and lower(status) not in ('closed','recovered') and sla_due_at<now();
  select count(*) into cv from public.vulnerabilities where organization_id=p_org and lower(coalesce(severity,''))='critical' and lower(coalesce(status,'')) not in ('closed','resolved','remediated');
  select count(*) into ai from public.soc_threat_indicators where organization_id=p_org and enabled=true and (expires_at is null or expires_at>now());
  select count(*) into im from public.soc_indicator_matches where organization_id=p_org and created_at>now()-interval '24 hours';
  select count(*) into qr from public.soc_response_actions where organization_id=p_org and lower(status) in ('pending_approval','approved');

  threat:=least(100,oa*4 + im*5 + cv*8);
  exposure:=least(100,cv*10 + oi*4 + od*8);
  response:=greatest(0,100 - least(100,od*20 + qr*5));
  risk:=round(least(100,(threat+exposure+(100-response))/3),2);

  insert into public.soc_analytics_snapshots(
    organization_id,risk_score,exposure_score,threat_score,response_score,
    open_alerts,open_incidents,overdue_incidents,critical_vulnerabilities,
    active_indicators,indicator_matches,queued_response_actions,metrics
  ) values(
    p_org,risk,exposure,threat,response,oa,oi,od,cv,ai,im,qr,
    jsonb_build_object('generated_by','CyberTech 360 deterministic analytics','window','24h')
  ) returning id into sid;

  return jsonb_build_object('snapshot_id',sid,'risk_score',risk,'exposure_score',exposure,'threat_score',threat,'response_score',response,'open_alerts',oa,'open_incidents',oi,'overdue_incidents',od,'critical_vulnerabilities',cv,'active_indicators',ai,'indicator_matches',im,'queued_response_actions',qr);
end;
$$;

revoke all on function public.run_v25_soc_analytics(uuid) from public,anon,authenticated;
grant execute on function public.run_v25_soc_analytics(uuid) to authenticated,service_role;

create or replace function public.queue_v25_response_actions(p_org uuid)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare a record; queued integer:=0;
begin
  if not public.v25_soc_analytics_can_write(p_org) and current_user <> 'service_role' then raise exception 'forbidden'; end if;
  for a in
    select * from public.soc_alerts
    where organization_id=p_org and lower(severity) in ('critical','high')
      and lower(status) not in ('closed','resolved')
    order by created_at desc limit 100
  loop
    if not exists(select 1 from public.soc_response_actions r where r.organization_id=p_org and r.alert_id=a.id and lower(r.status) in ('pending_approval','approved','executed')) then
      insert into public.soc_response_actions(organization_id,alert_id,action_type,target_type,target_value,reason,approval_required)
      values(p_org,a.id,
        case when lower(a.severity)='critical' then 'escalate_case' else 'collect_evidence' end,
        'soc_alert',''||a.id,
        'Deterministic Phase 6 response recommendation generated from high/critical SOC alert',true);
      queued:=queued+1;
    end if;
  end loop;
  return jsonb_build_object('organization_id',p_org,'actions_queued',queued);
end;
$$;

revoke all on function public.queue_v25_response_actions(uuid) from public,anon;
grant execute on function public.queue_v25_response_actions(uuid) to authenticated,service_role;

create or replace view public.v25_soc_threat_intelligence
with (security_invoker=true)
as
select i.*,coalesce(m.matches,0) as recent_matches
from public.soc_threat_indicators i
left join lateral (
  select count(*) matches from public.soc_indicator_matches m
  where m.indicator_id=i.id and m.created_at>now()-interval '24 hours'
) m on true;

create or replace view public.v25_soc_response_queue
with (security_invoker=true)
as
select r.*,c.case_number,c.title as case_title
from public.soc_response_actions r
left join public.soc_incident_cases c on c.id=r.case_id;

grant select on public.v25_soc_threat_intelligence to authenticated;
grant select on public.v25_soc_response_queue to authenticated;

select 'V2.5 Phase 6 Advanced SOC Analytics schema ready' as status;
