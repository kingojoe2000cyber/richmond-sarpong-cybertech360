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
  set score=public.calculate_assessment_score(new.assessment_id)
  where id=new.assessment_id;
  return new;
end;
$$;
drop trigger if exists refresh_assessment_score on public.assessment_items;
create trigger refresh_assessment_score after insert or update or delete on public.assessment_items
for each row execute function public.refresh_assessment_score();
