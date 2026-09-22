-- CyberTech 360 V2.4 Continuous Compliance & Security Operations
create table if not exists public.monitoring_checks(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 check_code text not null, name text not null, check_type text not null, target_type text, target_id uuid,
 expected_status text, actual_status text default 'unknown', score numeric(5,2) default 0,
 last_run_at timestamptz, next_run_at timestamptz, enabled boolean default true,
 details jsonb default '{}'::jsonb, created_at timestamptz default now(), unique(organization_id,check_code));
create table if not exists public.monitoring_results(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 check_id uuid not null references public.monitoring_checks(id) on delete cascade, status text not null,
 score numeric(5,2) default 0, observed_at timestamptz default now(), evidence_hash text, details jsonb default '{}'::jsonb);
create table if not exists public.evidence_collection_jobs(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 job_code text not null, source_type text not null, source_name text not null, schedule text, status text default 'pending',
 last_run_at timestamptz, next_run_at timestamptz, records_collected integer default 0, error_message text,
 created_at timestamptz default now(), unique(organization_id,job_code));
create table if not exists public.vulnerability_sla_policies(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 severity text not null, cvss_min numeric(3,1), cvss_max numeric(3,1), days_to_due integer not null,
 active boolean default true, unique(organization_id,severity));
create table if not exists public.security_metrics(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 metric_code text not null, metric_name text not null, metric_value numeric, unit text, target_value numeric,
 status text, period_start date, period_end date, calculated_at timestamptz default now(), details jsonb default '{}'::jsonb);
create table if not exists public.compliance_schedules(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 name text not null, framework_id uuid references public.frameworks(id), frequency text not null, next_run_at timestamptz,
 last_run_at timestamptz, enabled boolean default true, owner_id uuid references public.profiles(id), created_at timestamptz default now());
create table if not exists public.siem_events(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 source text not null, external_event_id text, event_time timestamptz not null, severity text, event_type text,
 source_ip inet, username text, message text, raw_event jsonb default '{}'::jsonb, normalized jsonb default '{}'::jsonb,
 received_at timestamptz default now(), unique(organization_id,source,external_event_id));
create table if not exists public.evidence_chain(
 id bigserial primary key, organization_id uuid not null references public.organizations(id) on delete cascade,
 evidence_id uuid references public.evidence(id) on delete set null, event_type text not null, content_hash text not null,
 previous_hash text, actor_id uuid references public.profiles(id), created_at timestamptz default now(), metadata jsonb default '{}'::jsonb);
create table if not exists public.notification_escalations(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 notification_id uuid not null references public.notifications(id) on delete cascade, escalation_level integer not null default 1,
 escalate_after_minutes integer not null, escalated_at timestamptz, recipient_id uuid references public.profiles(id),
 status text default 'pending', created_at timestamptz default now());
create table if not exists public.ai_investigations(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 title text not null, prompt text not null, status text default 'open', severity text default 'medium',
 findings jsonb default '[]'::jsonb, related_records jsonb default '[]'::jsonb, recommendation text,
 created_by uuid references public.profiles(id), created_at timestamptz default now(), completed_at timestamptz);

alter table public.monitoring_checks enable row level security;
alter table public.monitoring_results enable row level security;
alter table public.evidence_collection_jobs enable row level security;
alter table public.vulnerability_sla_policies enable row level security;
alter table public.security_metrics enable row level security;
alter table public.compliance_schedules enable row level security;
alter table public.siem_events enable row level security;
alter table public.evidence_chain enable row level security;
alter table public.notification_escalations enable row level security;
alter table public.ai_investigations enable row level security;

create or replace function public.v24_can_write() returns boolean language sql stable security definer set search_path=public
as $$ select public.current_role() in ('super_admin','grc_manager','security_manager','risk_manager','compliance_officer','soc_analyst','it_admin') $$;

do $$
declare t text;
begin
 foreach t in array array['monitoring_checks','monitoring_results','evidence_collection_jobs','vulnerability_sla_policies','security_metrics','compliance_schedules','siem_events','notification_escalations','ai_investigations'] loop
  execute format('drop policy if exists v24_select on public.%I',t);
  execute format('drop policy if exists v24_insert on public.%I',t);
  execute format('drop policy if exists v24_update on public.%I',t);
  execute format('drop policy if exists v24_delete on public.%I',t);
  execute format('create policy v24_select on public.%I for select to authenticated using (organization_id=public.current_org_id())',t);
  execute format('create policy v24_insert on public.%I for insert to authenticated with check (organization_id=public.current_org_id() and public.v24_can_write())',t);
  execute format('create policy v24_update on public.%I for update to authenticated using (organization_id=public.current_org_id() and public.v24_can_write()) with check (organization_id=public.current_org_id() and public.v24_can_write())',t);
  execute format('create policy v24_delete on public.%I for delete to authenticated using (organization_id=public.current_org_id() and public.v24_can_write())',t);
 end loop;
end $$;

create policy v24_chain_select on public.evidence_chain for select to authenticated using (organization_id=public.current_org_id());
revoke insert,update,delete on public.evidence_chain from authenticated;

create or replace function public.append_evidence_chain(p_evidence_id uuid,p_event_type text,p_content_hash text,p_metadata jsonb default '{}'::jsonb)
returns bigint language plpgsql security definer set search_path=public as $$
declare prev text; new_id bigint;
begin
 if not public.v24_can_write() then raise exception 'insufficient_role'; end if;
 if p_evidence_id is not null and not exists(select 1 from public.evidence e where e.id=p_evidence_id and e.organization_id=public.current_org_id()) then raise exception 'evidence_not_in_tenant'; end if;
 select content_hash into prev from public.evidence_chain where organization_id=public.current_org_id() order by id desc limit 1;
 insert into public.evidence_chain(organization_id,evidence_id,event_type,content_hash,previous_hash,actor_id,metadata)
 values(public.current_org_id(),p_evidence_id,p_event_type,p_content_hash,prev,auth.uid(),coalesce(p_metadata,'{}'::jsonb)) returning id into new_id;
 return new_id;
end $$;

create or replace function public.calculate_vulnerability_due(p_cvss numeric,p_severity text) returns date language sql stable as $$
 select current_date + greatest(0,coalesce((select days_to_due from public.vulnerability_sla_policies
 where organization_id=public.current_org_id() and active=true and lower(severity)=lower(coalesce(p_severity,''))
 and coalesce(p_cvss,0) between coalesce(cvss_min,0) and coalesce(cvss_max,10) order by days_to_due limit 1),
 case when coalesce(p_cvss,0)>=9 then 7 when coalesce(p_cvss,0)>=7 then 15 when coalesce(p_cvss,0)>=4 then 30 else 90 end));
$$;

create or replace view public.vulnerability_sla_status as
select v.*,public.calculate_vulnerability_due(v.cvss,v.severity) calculated_due_date,
case when v.status in ('closed','resolved','complete') then 'closed'
when public.calculate_vulnerability_due(v.cvss,v.severity)<current_date then 'overdue'
when public.calculate_vulnerability_due(v.cvss,v.severity)<=current_date+7 then 'due_soon' else 'on_track' end sla_state
from public.vulnerabilities v where v.organization_id=public.current_org_id();

create or replace function public.calculate_security_kpis() returns void language plpgsql security definer set search_path=public as $$
declare org uuid:=public.current_org_id(); total_c int; eff numeric; open_r int; overdue_r int; crit_v int; evidence_ok numeric;
begin
 select count(*),coalesce(avg(effectiveness),0) into total_c,eff from public.controls where organization_id=org;
 select count(*) filter(where status not in ('closed','resolved','complete')),count(*) filter(where due_date<current_date and status not in ('closed','resolved','complete')) into open_r,overdue_r from public.remediations where organization_id=org;
 select count(*) into crit_v from public.vulnerabilities where organization_id=org and coalesce(cvss,0)>=9 and status not in ('closed','resolved','complete');
 select coalesce(avg(case when status='approved' then 100 when status='needs_update' then 50 else 0 end),0) into evidence_ok from public.evidence where organization_id=org;
 insert into public.security_metrics(organization_id,metric_code,metric_name,metric_value,unit,target_value,status,period_start,period_end,details) values
 (org,'CONTROL_EFFECTIVENESS','Average control effectiveness',eff,'percent',90,case when eff>=90 then 'green' when eff>=75 then 'amber' else 'red' end,current_date,current_date,jsonb_build_object('control_count',total_c)),
 (org,'OPEN_REMEDIATIONS','Open remediations',open_r,'count',10,case when open_r<=10 then 'green' when open_r<=25 then 'amber' else 'red' end,current_date,current_date,'{}'),
 (org,'OVERDUE_REMEDIATIONS','Overdue remediations',overdue_r,'count',0,case when overdue_r=0 then 'green' when overdue_r<=5 then 'amber' else 'red' end,current_date,current_date,'{}'),
 (org,'CRITICAL_VULNERABILITIES','Critical CVSS vulnerabilities',crit_v,'count',0,case when crit_v=0 then 'green' else 'red' end,current_date,current_date,'{}'),
 (org,'EVIDENCE_READINESS','Evidence approval readiness',evidence_ok,'percent',90,case when evidence_ok>=90 then 'green' when evidence_ok>=75 then 'amber' else 'red' end,current_date,current_date,'{}');
end $$;

create or replace function public.run_continuous_monitoring() returns integer language plpgsql security definer set search_path=public as $$
declare n integer:=0; c record; st text; sc numeric;
begin
 for c in select * from public.monitoring_checks where organization_id=public.current_org_id() and enabled=true loop
  st:='pass'; sc:=100;
  if c.target_type='remediation' and exists(select 1 from public.remediations r where r.id=c.target_id and r.organization_id=c.organization_id and r.status not in ('closed','resolved','complete') and r.due_date<current_date) then st:='fail'; sc:=0;
  elsif c.target_type='vulnerability' and exists(select 1 from public.vulnerabilities v where v.id=c.target_id and v.organization_id=c.organization_id and v.status not in ('closed','resolved','complete') and public.calculate_vulnerability_due(v.cvss,v.severity)<current_date) then st:='fail'; sc:=0;
  elsif c.target_type='evidence' and exists(select 1 from public.evidence e where e.id=c.target_id and e.organization_id=c.organization_id and coalesce(e.status,'pending')<>'approved') then st:='fail'; sc:=0; end if;
  insert into public.monitoring_results(organization_id,check_id,status,score,details) values(c.organization_id,c.id,st,sc,jsonb_build_object('check_type',c.check_type));
  update public.monitoring_checks set actual_status=st,score=sc,last_run_at=now() where id=c.id; n:=n+1;
 end loop;
 perform public.calculate_security_kpis(); return n;
end $$;

insert into public.vulnerability_sla_policies(organization_id,severity,cvss_min,cvss_max,days_to_due)
select o.id,x.severity,x.min,x.max,x.days from public.organizations o cross join
(values ('critical',9.0,10.0,7),('high',7.0,8.9,15),('medium',4.0,6.9,30),('low',0.0,3.9,90)) x(severity,min,max,days)
on conflict (organization_id,severity) do nothing;

create index if not exists idx_monitoring_checks_org on public.monitoring_checks(organization_id,enabled,next_run_at);
create index if not exists idx_monitoring_results_check on public.monitoring_results(check_id,observed_at desc);
create index if not exists idx_siem_events_org_time on public.siem_events(organization_id,event_time desc);
create index if not exists idx_security_metrics_org_time on public.security_metrics(organization_id,calculated_at desc);
create index if not exists idx_evidence_chain_org_id on public.evidence_chain(organization_id,id desc);
create index if not exists idx_ai_investigations_org on public.ai_investigations(organization_id,created_at desc);

drop policy if exists v23_insert on public.evidence_reviews;
create policy v23_insert on public.evidence_reviews for insert to authenticated
with check (organization_id=public.current_org_id() and public.current_role() in ('super_admin','grc_manager','security_manager','compliance_officer','auditor','it_admin'));
