-- CyberTech 360 V2.2 Production Readiness
-- Apply after schema.sql. Designed for Supabase/PostgreSQL.
create or replace function public.current_org_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select organization_id from public.profiles where id = auth.uid() limit 1;
$$;

revoke all on function public.current_org_id() from public;
grant execute on function public.current_org_id() to authenticated;

create index if not exists idx_profiles_org on public.profiles(organization_id);
create index if not exists idx_risks_org on public.risks(organization_id);
create index if not exists idx_controls_org on public.controls(organization_id);
create index if not exists idx_evidence_org on public.evidence(organization_id);
create index if not exists idx_incidents_org on public.incidents(organization_id);
create index if not exists idx_assets_org on public.assets(organization_id);
create index if not exists idx_vulnerabilities_org on public.vulnerabilities(organization_id);
create index if not exists idx_vendors_org on public.vendors(organization_id);
create index if not exists idx_audits_org on public.audits(organization_id);

-- Tenant isolation policies. Adjust role claims only if custom roles are introduced.
do $$
declare t text;
begin
  foreach t in array array['risks','controls','evidence','incidents','assets','vulnerabilities','vendors','audits'] loop
    execute format('drop policy if exists tenant_isolation on public.%I', t);
    execute format('create policy tenant_isolation on public.%I for all to authenticated using (organization_id = public.current_org_id()) with check (organization_id = public.current_org_id())', t);
  end loop;
end $$;

-- Evidence integrity metadata.
alter table public.evidence add column if not exists sha256 text;
alter table public.evidence add column if not exists storage_path text;
alter table public.evidence add column if not exists verified_at timestamptz;

-- Immutable audit log: application/service layer should be the only writer.
alter table public.audit_log enable row level security;
drop policy if exists audit_log_read_org on public.audit_log;
create policy audit_log_read_org on public.audit_log
for select to authenticated
using (organization_id = public.current_org_id());

-- Risk scoring helper.
create or replace function public.calculate_inherent_risk(likelihood numeric, impact numeric)
returns numeric
language sql
immutable
as $$ select round(greatest(0, least(25, coalesce(likelihood,0) * coalesce(impact,0))), 2) $$;

-- Basic compliance assessment structure.
create table if not exists public.assessments (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  framework_id uuid references public.frameworks(id) on delete set null,
  name text not null,
  status text not null default 'draft',
  score numeric(5,2) default 0,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now()
);
alter table public.assessments enable row level security;
drop policy if exists assessments_tenant on public.assessments;
create policy assessments_tenant on public.assessments
for all to authenticated using (organization_id = public.current_org_id()) with check (organization_id = public.current_org_id());

create index if not exists idx_assessments_org on public.assessments(organization_id);

-- Remediation tracking.
create table if not exists public.remediations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  title text not null,
  description text,
  owner_id uuid references public.profiles(id) on delete set null,
  priority text not null default 'medium',
  status text not null default 'open',
  due_date date,
  risk_id uuid references public.risks(id) on delete set null,
  control_id uuid references public.controls(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.remediations enable row level security;
drop policy if exists remediations_tenant on public.remediations;
create policy remediations_tenant on public.remediations
for all to authenticated using (organization_id = public.current_org_id()) with check (organization_id = public.current_org_id());
create index if not exists idx_remediations_org_status on public.remediations(organization_id,status);
