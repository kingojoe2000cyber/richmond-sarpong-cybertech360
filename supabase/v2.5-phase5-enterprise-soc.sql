-- CyberTech 360 V2.5 Phase 5
-- Enterprise SOC Intelligence & Incident Response
-- No external AI dependency.
-- Safe to rerun.

create extension if not exists pgcrypto;

create table if not exists public.soc_incident_cases (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  alert_id uuid references public.soc_alerts(id) on delete set null,
  incident_id uuid references public.incidents(id) on delete set null,
  case_number text not null,
  title text not null,
  description text,
  severity text not null default 'high' check (lower(severity) in ('critical','high','medium','low')),
  priority text not null default 'high' check (lower(priority) in ('critical','high','medium','low')),
  status text not null default 'new' check (lower(status) in ('new','acknowledged','investigating','contained','eradicated','recovered','closed')),
  assignee_id uuid references public.profiles(id) on delete set null,
  detected_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  contained_at timestamptz,
  resolved_at timestamptz,
  sla_due_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, case_number)
);

create index if not exists idx_soc_incident_cases_org_queue
  on public.soc_incident_cases(organization_id, status, severity, updated_at desc);

create table if not exists public.soc_incident_tasks (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  case_id uuid not null references public.soc_incident_cases(id) on delete cascade,
  title text not null,
  description text,
  status text not null default 'open' check (lower(status) in ('open','in_progress','blocked','done')),
  priority text not null default 'medium' check (lower(priority) in ('critical','high','medium','low')),
  assignee_id uuid references public.profiles(id) on delete set null,
  due_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_incident_tasks_case
  on public.soc_incident_tasks(case_id, status, due_at);

create table if not exists public.soc_incident_timeline (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  case_id uuid not null references public.soc_incident_cases(id) on delete cascade,
  event_type text not null,
  actor_id uuid references public.profiles(id) on delete set null,
  message text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_incident_timeline_case
  on public.soc_incident_timeline(case_id, created_at desc);

create table if not exists public.soc_playbooks (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  trigger_type text not null,
  severity_min text not null default 'high',
  enabled boolean not null default true,
  steps jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, name)
);

create table if not exists public.soc_playbook_runs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  playbook_id uuid references public.soc_playbooks(id) on delete set null,
  case_id uuid references public.soc_incident_cases(id) on delete cascade,
  status text not null default 'queued',
  current_step integer not null default 0,
  output jsonb not null default '{}'::jsonb,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_playbook_runs_org
  on public.soc_playbook_runs(organization_id, created_at desc);

create table if not exists public.soc_threat_hunts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  hunt_name text not null,
  hypothesis text not null,
  query_text text,
  status text not null default 'planned',
  severity text not null default 'medium',
  findings_count integer not null default 0,
  started_at timestamptz,
  completed_at timestamptz,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_soc_threat_hunts_org
  on public.soc_threat_hunts(organization_id, status, created_at desc);

create table if not exists public.soc_escalations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  case_id uuid not null references public.soc_incident_cases(id) on delete cascade,
  level integer not null default 1,
  reason text not null,
  channel text not null default 'internal',
  status text not null default 'open',
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);

create index if not exists idx_soc_escalations_case
  on public.soc_escalations(case_id, status, created_at desc);

-- Default playbooks. They are deterministic response guides; no AI is required.
insert into public.soc_playbooks (organization_id,name,trigger_type,severity_min,steps)
select o.id, x.name, x.trigger_type, x.severity_min, x.steps::jsonb
from public.organizations o
cross join (
  values
    ('Authentication Brute Force Response','authentication_failure_burst','high',
     '[{"step":1,"action":"Validate source and target identity"},{"step":2,"action":"Review recent authentication failures"},{"step":3,"action":"Contain affected account or source"},{"step":4,"action":"Collect evidence and document findings"},{"step":5,"action":"Close or escalate based on evidence"}]'),
    ('Critical Security Event Response','critical_event','critical',
     '[{"step":1,"action":"Acknowledge alert"},{"step":2,"action":"Declare incident"},{"step":3,"action":"Contain affected assets"},{"step":4,"action":"Preserve evidence"},{"step":5,"action":"Escalate to security management"}]')
) x(name,trigger_type,severity_min,steps)
where not exists (
  select 1 from public.soc_playbooks p
  where p.organization_id=o.id and p.name=x.name
);

-- Tenant authorization helpers.
create or replace function public.v25_soc_ir_can_read(p_org uuid)
returns boolean
language sql
stable
security definer
set search_path=''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid())
      and p.organization_id = p_org
      and p.role in ('super_admin','grc_manager','security_manager','risk_manager',
                     'compliance_officer','auditor','soc_analyst','it_admin',
                     'executive','viewer')
  );
$$;

create or replace function public.v25_soc_ir_can_write(p_org uuid)
returns boolean
language sql
stable
security definer
set search_path=''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid())
      and p.organization_id = p_org
      and p.role in ('super_admin','grc_manager','security_manager','risk_manager',
                     'compliance_officer','it_admin','soc_analyst')
  );
$$;

-- RLS and grants.
do $$
declare t text;
begin
  foreach t in array array[
    'soc_incident_cases','soc_incident_tasks','soc_incident_timeline',
    'soc_playbooks','soc_playbook_runs','soc_threat_hunts','soc_escalations'
  ] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on table public.%I from anon', t);
    execute format('grant select, insert, update, delete on table public.%I to authenticated', t);
    execute format('grant all on table public.%I to service_role', t);
  end loop;
end $$;

drop policy if exists soc_ir_cases_select on public.soc_incident_cases;
create policy soc_ir_cases_select on public.soc_incident_cases for select to authenticated
using (public.v25_soc_ir_can_read(organization_id));
drop policy if exists soc_ir_cases_write on public.soc_incident_cases;
create policy soc_ir_cases_write on public.soc_incident_cases for all to authenticated
using (public.v25_soc_ir_can_write(organization_id))
with check (public.v25_soc_ir_can_write(organization_id));

drop policy if exists soc_ir_tasks_select on public.soc_incident_tasks;
create policy soc_ir_tasks_select on public.soc_incident_tasks for select to authenticated
using (public.v25_soc_ir_can_read(organization_id));
drop policy if exists soc_ir_tasks_write on public.soc_incident_tasks;
create policy soc_ir_tasks_write on public.soc_incident_tasks for all to authenticated
using (public.v25_soc_ir_can_write(organization_id))
with check (public.v25_soc_ir_can_write(organization_id));

drop policy if exists soc_ir_timeline_select on public.soc_incident_timeline;
create policy soc_ir_timeline_select on public.soc_incident_timeline for select to authenticated
using (public.v25_soc_ir_can_read(organization_id));
drop policy if exists soc_ir_timeline_write on public.soc_incident_timeline;
create policy soc_ir_timeline_write on public.soc_incident_timeline for all to authenticated
using (public.v25_soc_ir_can_write(organization_id))
with check (public.v25_soc_ir_can_write(organization_id));

drop policy if exists soc_ir_playbooks_select on public.soc_playbooks;
create policy soc_ir_playbooks_select on public.soc_playbooks for select to authenticated
using (public.v25_soc_ir_can_read(organization_id));
drop policy if exists soc_ir_playbooks_write on public.soc_playbooks;
create policy soc_ir_playbooks_write on public.soc_playbooks for all to authenticated
using (public.v25_soc_ir_can_write(organization_id))
with check (public.v25_soc_ir_can_write(organization_id));

drop policy if exists soc_ir_playbook_runs_select on public.soc_playbook_runs;
create policy soc_ir_playbook_runs_select on public.soc_playbook_runs for select to authenticated
using (public.v25_soc_ir_can_read(organization_id));
drop policy if exists soc_ir_playbook_runs_write on public.soc_playbook_runs;
create policy soc_ir_playbook_runs_write on public.soc_playbook_runs for all to authenticated
using (public.v25_soc_ir_can_write(organization_id))
with check (public.v25_soc_ir_can_write(organization_id));

drop policy if exists soc_ir_hunts_select on public.soc_threat_hunts;
create policy soc_ir_hunts_select on public.soc_threat_hunts for select to authenticated
using (public.v25_soc_ir_can_read(organization_id));
drop policy if exists soc_ir_hunts_write on public.soc_threat_hunts;
create policy soc_ir_hunts_write on public.soc_threat_hunts for all to authenticated
using (public.v25_soc_ir_can_write(organization_id))
with check (public.v25_soc_ir_can_write(organization_id));

drop policy if exists soc_ir_escalations_select on public.soc_escalations;
create policy soc_ir_escalations_select on public.soc_escalations for select to authenticated
using (public.v25_soc_ir_can_read(organization_id));
drop policy if exists soc_ir_escalations_write on public.soc_escalations;
create policy soc_ir_escalations_write on public.soc_escalations for all to authenticated
using (public.v25_soc_ir_can_write(organization_id))
with check (public.v25_soc_ir_can_write(organization_id));

-- Create an incident response case from an open SOC alert.
create or replace function public.create_v25_incident_from_alert(p_org uuid,p_alert_id uuid)
returns jsonb
language plpgsql
security definer
set search_path=''
as $$
declare
  a record;
  c public.soc_incident_cases;
  case_no text;
  sla interval;
begin
  select * into a
  from public.soc_alerts
  where id=p_alert_id and organization_id=p_org
  limit 1;
  if not found then raise exception 'alert_not_found'; end if;

  select case_number into case_no
  from public.soc_incident_cases
  where organization_id=p_org and alert_id=p_alert_id
  limit 1;
  if case_no is not null then
    select * into c from public.soc_incident_cases where organization_id=p_org and case_number=case_no;
    return jsonb_build_object('case_id',c.id,'case_number',c.case_number,'created',false);
  end if;

  sla := case lower(a.severity)
    when 'critical' then interval '1 hour'
    when 'high' then interval '4 hours'
    when 'medium' then interval '8 hours'
    else interval '24 hours'
  end;

  case_no := 'CT360-IR-' || to_char(now(),'YYYYMMDD-HH24MISS') || '-' ||
             upper(substr(replace(gen_random_uuid()::text,'-',''),1,6));

  insert into public.soc_incident_cases(
    organization_id,alert_id,case_number,title,description,severity,priority,status,
    detected_at,sla_due_at
  )
  values(
    p_org,p_alert_id,case_no,
    coalesce(a.title,'SOC Security Incident'),
    'Created from SOC alert '||p_alert_id::text,
    lower(coalesce(a.severity,'high')),
    lower(coalesce(a.severity,'high')),
    'new',
    coalesce(a.first_seen_at,now()),
    now()+sla
  )
  returning * into c;

  insert into public.soc_incident_timeline(
    organization_id,case_id,event_type,actor_id,message,metadata
  ) values(
    p_org,c.id,'incident_created',auth.uid(),
    'Incident response case created from SOC alert',
    jsonb_build_object('alert_id',p_alert_id,'severity',a.severity)
  );

  update public.soc_alerts
  set incident_id=c.id, status='investigating', updated_at=now()
  where id=p_alert_id and organization_id=p_org;

  return jsonb_build_object('case_id',c.id,'case_number',c.case_number,'created',true);
end;
$$;

revoke all on function public.create_v25_incident_from_alert(uuid,uuid) from public,anon,authenticated;
grant execute on function public.create_v25_incident_from_alert(uuid,uuid) to service_role;

-- Deterministic status transition and timeline.
create or replace function public.advance_v25_incident(p_org uuid,p_case_id uuid,p_status text,p_message text default null)
returns jsonb
language plpgsql
security definer
set search_path=''
as $$
declare c public.soc_incident_cases; msg text;
begin
  select * into c from public.soc_incident_cases where id=p_case_id and organization_id=p_org for update;
  if not found then raise exception 'incident_case_not_found'; end if;
  if lower(p_status) not in ('new','acknowledged','investigating','contained','eradicated','recovered','closed') then
    raise exception 'invalid_incident_status';
  end if;
  update public.soc_incident_cases
  set status=lower(p_status),
      acknowledged_at=case when lower(p_status) in ('acknowledged','investigating','contained','eradicated','recovered','closed') then coalesce(acknowledged_at,now()) else acknowledged_at end,
      contained_at=case when lower(p_status) in ('contained','eradicated','recovered','closed') then coalesce(contained_at,now()) else contained_at end,
      resolved_at=case when lower(p_status)='closed' then coalesce(resolved_at,now()) else resolved_at end,
      updated_at=now()
  where id=p_case_id and organization_id=p_org
  returning * into c;
  msg:=coalesce(p_message,'Status changed to '||c.status);
  insert into public.soc_incident_timeline(organization_id,case_id,event_type,actor_id,message)
  values(p_org,c.id,'status_change',auth.uid(),msg);
  return jsonb_build_object('case_id',c.id,'status',c.status);
end;
$$;

revoke all on function public.advance_v25_incident(uuid,uuid,text,text) from public,anon,authenticated;
grant execute on function public.advance_v25_incident(uuid,uuid,text,text) to service_role;

-- SLA/escalation worker, intended for cron/worker execution.
create or replace function public.run_v25_incident_sla(p_org uuid)
returns jsonb
language plpgsql
security definer
set search_path=''
as $$
declare c record; escalated integer:=0; overdue integer:=0;
begin
  for c in
    select *
    from public.soc_incident_cases
    where organization_id=p_org
      and lower(status) not in ('closed','recovered')
      and sla_due_at is not null
      and sla_due_at < now()
    order by sla_due_at
  loop
    overdue:=overdue+1;
    if not exists (
      select 1 from public.soc_escalations e
      where e.case_id=c.id and e.status='open' and e.reason like 'SLA overdue%'
    ) then
      insert into public.soc_escalations(organization_id,case_id,level,reason,channel)
      values(p_org,c.id,2,'SLA overdue — automatic escalation','internal');
      insert into public.soc_incident_timeline(organization_id,case_id,event_type,message,metadata)
      values(p_org,c.id,'sla_escalation','Incident SLA is overdue; escalation created',
             jsonb_build_object('sla_due_at',c.sla_due_at));
      escalated:=escalated+1;
    end if;
  end loop;
  return jsonb_build_object('organization_id',p_org,'overdue',overdue,'escalated',escalated);
end;
$$;

revoke all on function public.run_v25_incident_sla(uuid) from public,anon,authenticated;
grant execute on function public.run_v25_incident_sla(uuid) to service_role;

create or replace view public.v25_soc_incident_dashboard
with (security_invoker=true)
as
select
  c.*,
  case when c.sla_due_at is not null and c.sla_due_at < now()
       and lower(c.status) not in ('closed','recovered') then true else false end as sla_overdue,
  coalesce((select count(*) from public.soc_incident_tasks t where t.case_id=c.id and lower(t.status)<>'done'),0) as open_tasks,
  coalesce((select count(*) from public.soc_incident_timeline tl where tl.case_id=c.id),0) as timeline_events
from public.soc_incident_cases c;

create or replace view public.v25_soc_mttr_metrics
with (security_invoker=true)
as
select
  c.organization_id,
  count(*) filter (where lower(c.status)<>'closed') as open_incidents,
  count(*) filter (where c.sla_due_at is not null and c.sla_due_at < now() and lower(c.status) not in ('closed','recovered')) as overdue_incidents,
  round(avg(extract(epoch from (coalesce(c.acknowledged_at,c.created_at)-c.detected_at))/60.0) filter (where c.acknowledged_at is not null),2) as avg_mtta_minutes,
  round(avg(extract(epoch from (c.resolved_at-c.detected_at))/60.0) filter (where c.resolved_at is not null),2) as avg_mttr_minutes,
  count(*) as total_incidents
from public.soc_incident_cases c
group by c.organization_id;

grant select on public.v25_soc_incident_dashboard to authenticated;
grant select on public.v25_soc_mttr_metrics to authenticated;

-- Verification.
select 'V2.5 Phase 5 Enterprise SOC Intelligence schema ready' as status;
select table_name
from information_schema.tables
where table_schema='public'
and table_name in (
 'soc_incident_cases','soc_incident_tasks','soc_incident_timeline',
 'soc_playbooks','soc_playbook_runs','soc_threat_hunts','soc_escalations'
)
order by table_name;
