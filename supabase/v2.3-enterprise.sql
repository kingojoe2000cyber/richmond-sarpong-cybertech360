-- CyberTech 360 V2.3 Enterprise Intelligence & Evidence Automation
create table if not exists public.pci_requirements(
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 requirement_code text not null,title text not null,description text,testing_procedure text,priority text default 'normal',
 unique(organization_id,requirement_code));
create table if not exists public.evidence_reviews(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 evidence_id uuid not null references public.evidence(id) on delete cascade,reviewer_id uuid references public.profiles(id),
 decision text not null default 'pending' check(decision in ('pending','approved','rejected','needs_update')),
 comments text,reviewed_at timestamptz,created_at timestamptz default now());
create table if not exists public.sla_policies(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 name text not null,severity text not null,days_to_due integer not null check(days_to_due>=0),active boolean default true);
create table if not exists public.notifications(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 recipient_id uuid references public.profiles(id) on delete cascade,notification_type text not null,title text not null,message text not null,
 severity text default 'info',read_at timestamptz,entity_type text,entity_id text,created_at timestamptz default now());
create table if not exists public.vendor_assessments(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 vendor_id uuid not null references public.vendors(id) on delete cascade,security_score numeric(5,2) default 0,
 inherent_risk numeric(5,2) default 0,residual_risk numeric(5,2) default 0,status text default 'open',
 findings text,assessed_at timestamptz,assessor_id uuid references public.profiles(id));
create table if not exists public.bia_processes(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 process_code text not null,name text not null,owner_id uuid references public.profiles(id),criticality text,
 rto_hours numeric(8,2),rpo_hours numeric(8,2),maximum_tolerable_downtime_hours numeric(8,2),
 dependencies text,recovery_priority integer,created_at timestamptz default now());
create table if not exists public.bcp_plans(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 plan_code text not null,name text not null,status text default 'draft',owner_id uuid references public.profiles(id),
 last_tested_at timestamptz,next_test_due date,version text,created_at timestamptz default now());
create table if not exists public.dr_plans(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 plan_code text not null,name text not null,status text default 'draft',owner_id uuid references public.profiles(id),
 recovery_strategy text,last_tested_at timestamptz,next_test_due date,created_at timestamptz default now());
create table if not exists public.ai_copilot_sessions(
 id uuid primary key default gen_random_uuid(),organization_id uuid not null references public.organizations(id) on delete cascade,
 user_id uuid references public.profiles(id),title text default 'GRC Copilot',created_at timestamptz default now(),last_used_at timestamptz default now());
create table if not exists public.ai_copilot_messages(
 id uuid primary key default gen_random_uuid(),session_id uuid not null references public.ai_copilot_sessions(id) on delete cascade,
 organization_id uuid not null references public.organizations(id) on delete cascade,user_id uuid references public.profiles(id),
role text not null check(role in ('user','assistant','system')),content text not null,created_at timestamptz default now());

alter table public.pci_requirements enable row level security;
alter table public.evidence_reviews enable row level security;
alter table public.sla_policies enable row level security;
alter table public.notifications enable row level security;
alter table public.vendor_assessments enable row level security;
alter table public.bia_processes enable row level security;
alter table public.bcp_plans enable row level security;
alter table public.dr_plans enable row level security;
alter table public.ai_copilot_sessions enable row level security;
alter table public.ai_copilot_messages enable row level security;

create or replace function public.v23_can_write() returns boolean language sql stable security definer set search_path=public
as $$ select public.current_role() in ('super_admin','grc_manager','security_manager','risk_manager','compliance_officer','it_admin') $$;

do $$
declare t text;
begin
 foreach t in array array['pci_requirements','evidence_reviews','sla_policies','notifications','vendor_assessments','bia_processes','bcp_plans','dr_plans','ai_copilot_sessions','ai_copilot_messages'] loop
  execute format('create policy v23_select on public.%I for select to authenticated using (organization_id=public.current_org_id())',t);
  execute format('create policy v23_insert on public.%I for insert to authenticated with check (organization_id=public.current_org_id() and public.v23_can_write())',t);
  execute format('create policy v23_update on public.%I for update to authenticated using (organization_id=public.current_org_id() and public.v23_can_write()) with check (organization_id=public.current_org_id() and public.v23_can_write())',t);
  execute format('create policy v23_delete on public.%I for delete to authenticated using (organization_id=public.current_org_id() and public.v23_can_write())',t);
 end loop;
end $$;

create index if not exists idx_evidence_reviews_evidence on public.evidence_reviews(evidence_id);
create index if not exists idx_notifications_recipient on public.notifications(recipient_id,read_at,created_at desc);
create index if not exists idx_vendor_assessments_vendor on public.vendor_assessments(vendor_id);
create index if not exists idx_bia_org on public.bia_processes(organization_id);
create index if not exists idx_bcp_org on public.bcp_plans(organization_id);
create index if not exists idx_dr_org on public.dr_plans(organization_id);

create or replace view public.remediation_sla as
select r.*, greatest(0, (coalesce(r.due_date,current_date)-current_date)) as days_remaining,
 case when r.due_date is null then 'no_due_date'
      when r.status in ('closed','resolved','complete') then 'closed'
      when r.due_date < current_date then 'overdue'
      when r.due_date <= current_date+7 then 'due_soon' else 'on_track' end as sla_state
from public.remediations r where r.organization_id=public.current_org_id();

create or replace view public.vendor_risk_summary as
select v.id,v.vendor_code,v.name,v.tier,v.risk_score,v.status,
 coalesce(va.security_score,0) security_score,coalesce(va.residual_risk,0) residual_risk,
 case when coalesce(va.residual_risk,v.risk_score,0)>=75 then 'critical'
      when coalesce(va.residual_risk,v.risk_score,0)>=50 then 'high'
      when coalesce(va.residual_risk,v.risk_score,0)>=25 then 'medium' else 'low' end as risk_band
from public.vendors v left join lateral
 (select * from public.vendor_assessments x where x.vendor_id=v.id order by x.assessed_at desc nulls last limit 1) va on true
where v.organization_id=public.current_org_id();

create or replace function public.create_sla_notifications()
returns integer language plpgsql security definer set search_path=public as $$
declare n integer:=0; r record;
begin
 for r in select id,organization_id,title,due_date,owner_id from public.remediations
 where organization_id=public.current_org_id() and status not in ('closed','resolved','complete') and due_date is not null
 and due_date <= current_date+7 loop
  if not exists(select 1 from public.notifications where entity_type='remediation' and entity_id=r.id::text and created_at::date=current_date) then
   insert into public.notifications(organization_id,recipient_id,notification_type,title,message,severity,entity_type,entity_id)
   values(r.organization_id,r.owner_id,'remediation_sla','Remediation SLA alert',r.title||' is due on '||r.due_date,
    case when r.due_date<current_date then 'critical' else 'warning' end,'remediation',r.id::text); n:=n+1;
  end if;
 end loop; return n;
end $$;

-- PCI DSS 4.0.1 top-level requirement library.
insert into public.pci_requirements(organization_id,requirement_code,title,description,priority)
select o.id,x.code,x.title,x.description,'high'
from public.organizations o
cross join (values
('1','Install and Maintain Network Security Controls','Network security controls are implemented and maintained.'),
('2','Apply Secure Configurations to All System Components','Secure configurations are established and maintained.'),
('3','Protect Stored Account Data','Stored account data is protected according to PCI DSS requirements.'),
('4','Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks','Strong cryptography protects cardholder data in transit.'),
('5','Protect All Systems and Networks from Malicious Software','Malicious software protections are implemented where applicable.'),
('6','Develop and Maintain Secure Systems and Software','Secure development and vulnerability management practices are maintained.'),
('7','Restrict Access to System Components and Cardholder Data by Business Need to Know','Access is restricted according to business need.'),
('8','Identify Users and Authenticate Access to System Components','Unique identification and authentication controls are implemented.'),
('9','Restrict Physical Access to Cardholder Data','Physical access to cardholder data and systems is controlled.'),
('10','Log and Monitor All Access to System Components and Cardholder Data','Logging and monitoring controls support detection and accountability.'),
('11','Regularly Test Security Systems and Processes','Security systems and processes are tested regularly.'),
('12','Support Information Security with Organizational Policies and Programs','Security policies, risk management and governance practices are maintained.')
) as x(code,title,description)
on conflict (organization_id,requirement_code) do nothing;
