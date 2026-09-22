-- CyberTech 360 V2.2.2 Compliance & PCI assessment engine
create table if not exists public.assessment_items (
  id uuid primary key default gen_random_uuid(),
  assessment_id uuid not null references public.assessments(id) on delete cascade,
  control_id uuid references public.controls(id) on delete set null,
  requirement_code text not null,
  title text not null,
  status text not null default 'not_assessed',
  score numeric(5,2) not null default 0 check(score between 0 and 100),
  evidence_required boolean not null default true,
  evidence_id uuid references public.evidence(id) on delete set null,
  finding text,
  remediation_id uuid references public.remediations(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.assessment_items enable row level security;
drop policy if exists assessment_items_tenant on public.assessment_items;
create policy assessment_items_tenant on public.assessment_items
for all to authenticated
using (assessment_id in (select id from public.assessments where organization_id=public.current_org_id()))
with check (assessment_id in (select id from public.assessments where organization_id=public.current_org_id()));

create index if not exists idx_assessment_items_assessment on public.assessment_items(assessment_id);
create index if not exists idx_assessment_items_status on public.assessment_items(status);

create or replace function public.calculate_assessment_score(p_assessment uuid)
returns numeric language sql stable security definer set search_path=public
as $$
  select coalesce(round(avg(score),2),0)
  from public.assessment_items ai
  join public.assessments a on a.id=ai.assessment_id
  where ai.assessment_id=p_assessment
    and a.organization_id=public.current_org_id();
$$;

-- Reusable PCI workspace metadata; requirement text should be populated from licensed/approved source material.
create table if not exists public.pci_scope_items (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  assessment_id uuid references public.assessments(id) on delete set null,
  component_name text not null,
  component_type text not null,
  data_flow_role text,
  in_cde boolean not null default false,
  segmentation_control text,
  owner_id uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);
alter table public.pci_scope_items enable row level security;
drop policy if exists pci_scope_tenant on public.pci_scope_items;
create policy pci_scope_tenant on public.pci_scope_items
for all to authenticated
using (organization_id=public.current_org_id())
with check (organization_id=public.current_org_id());

create index if not exists idx_pci_scope_org on public.pci_scope_items(organization_id);

-- Assessment score refresh.
create or replace function public.refresh_assessment_score()
returns trigger language plpgsql security definer set search_path=public
as $$
begin
  update public.assessments
  set score=public.calculate_assessment_score(coalesce(new.assessment_id, old.assessment_id))
  where id=coalesce(new.assessment_id, old.assessment_id);
  return new;
end;
$$;
drop trigger if exists refresh_assessment_score on public.assessment_items;
create trigger refresh_assessment_score after insert or update or delete on public.assessment_items
for each row execute function public.refresh_assessment_score();


-- V2.2.3: controlled write access for persistent GRC operations.
do $$
declare t text;
begin
  foreach t in array array['risks','controls','evidence','incidents','assets','vulnerabilities','vendors','audits','assessments','remediations','assessment_items','pci_scope_items'] loop
    execute format('drop policy if exists tenant_read_write on public.%I', t);
  end loop;
end $$;

-- Remove earlier permissive policies before adding role-aware policies.
do $
declare t text;
begin
  foreach t in array array['risks','controls','evidence','incidents','assets','vulnerabilities','vendors','audits'] loop
    execute format('drop policy if exists tenant_isolation on public.%I', t);
  end loop;
end $;
drop policy if exists assessments_tenant on public.assessments;
drop policy if exists remediations_tenant on public.remediations;
drop policy if exists assessment_items_tenant on public.assessment_items;
drop policy if exists pci_scope_tenant on public.pci_scope_items;

-- Replace broad tenant policies with role-aware write policies.
create or replace function public.can_write_gcr()
returns boolean language sql stable security definer set search_path=public
as $$ select public.current_role() in ('super_admin','grc_manager','security_manager','risk_manager','compliance_officer','it_admin') $$;
revoke all on function public.can_write_gcr() from public;
grant execute on function public.can_write_gcr() to authenticated;

do $$
declare t text;
begin
  foreach t in array array['risks','controls','evidence','incidents','assets','vulnerabilities','vendors','audits','assessments','remediations','assessment_items','pci_scope_items'] loop
    execute format('create policy tenant_select on public.%I for select to authenticated using (organization_id = public.current_org_id())', t);
    execute format('create policy tenant_insert on public.%I for insert to authenticated with check (organization_id = public.current_org_id() and public.can_write_gcr())', t);
    execute format('create policy tenant_update on public.%I for update to authenticated using (organization_id = public.current_org_id() and public.can_write_gcr()) with check (organization_id = public.current_org_id() and public.can_write_gcr())', t);
    execute format('create policy tenant_delete on public.%I for delete to authenticated using (organization_id = public.current_org_id() and public.can_write_gcr())', t);
  end loop;
end $$;

create index if not exists idx_audit_log_org_created on public.audit_log(organization_id,created_at desc);
create index if not exists idx_pci_scope_assessment on public.pci_scope_items(assessment_id);
