-- CyberTech 360 V2.2.1 Security Hardening
-- Apply after supabase/v2.2-production.sql

create or replace function public.current_role()
returns text language sql stable security definer set search_path = public
as $$ select role from public.profiles where id = auth.uid() limit 1 $$;
revoke all on function public.current_role() from public;
grant execute on function public.current_role() to authenticated;

drop policy if exists profiles_self_or_org on public.profiles;
create policy profiles_self_or_org on public.profiles
for select to authenticated
using (id = auth.uid() or organization_id = public.current_org_id());

drop policy if exists profiles_admin_write on public.profiles;
create policy profiles_admin_write on public.profiles
for update to authenticated
using (organization_id = public.current_org_id() and public.current_role() in ('super_admin','it_admin'))
with check (organization_id = public.current_org_id());

drop policy if exists frameworks_tenant on public.frameworks;
create policy frameworks_tenant on public.frameworks
for all to authenticated
using (organization_id = public.current_org_id())
with check (organization_id = public.current_org_id());

-- Audit history is read-only to browser sessions. Inserts come from trusted database triggers/service code.
drop policy if exists audit_log_insert on public.audit_log;
drop policy if exists audit_log_update on public.audit_log;
drop policy if exists audit_log_delete on public.audit_log;

create or replace function public.write_audit_event()
returns trigger language plpgsql security definer set search_path = public
as $$
declare org_id uuid;
begin
  org_id := coalesce(NEW.organization_id, OLD.organization_id);
  insert into public.audit_log(organization_id,actor_id,action,object_type,object_id,before_json,after_json)
  values (
    org_id, auth.uid(), tg_op, tg_table_name,
    coalesce(NEW.id,OLD.id)::text,
    case when tg_op in ('UPDATE','DELETE') then to_jsonb(OLD) end,
    case when tg_op in ('INSERT','UPDATE') then to_jsonb(NEW) end
  );
  return coalesce(NEW,OLD);
end;
$$;

drop trigger if exists audit_risks on public.risks;
create trigger audit_risks after insert or update or delete on public.risks for each row execute function public.write_audit_event();
drop trigger if exists audit_controls on public.controls;
create trigger audit_controls after insert or update or delete on public.controls for each row execute function public.write_audit_event();
drop trigger if exists audit_evidence on public.evidence;
create trigger audit_evidence after insert or update or delete on public.evidence for each row execute function public.write_audit_event();
drop trigger if exists audit_incidents on public.incidents;
create trigger audit_incidents after insert or update or delete on public.incidents for each row execute function public.write_audit_event();
drop trigger if exists audit_assets on public.assets;
create trigger audit_assets after insert or update or delete on public.assets for each row execute function public.write_audit_event();
drop trigger if exists audit_vulnerabilities on public.vulnerabilities;
create trigger audit_vulnerabilities after insert or update or delete on public.vulnerabilities for each row execute function public.write_audit_event();
drop trigger if exists audit_vendors on public.vendors;
create trigger audit_vendors after insert or update or delete on public.vendors for each row execute function public.write_audit_event();
drop trigger if exists audit_audits on public.audits;
create trigger audit_audits after insert or update or delete on public.audits for each row execute function public.write_audit_event();

insert into storage.buckets(id,name,public)
values ('cybertech-evidence','cybertech-evidence',false)
on conflict (id) do update set public=false;

drop policy if exists evidence_storage_read on storage.objects;
create policy evidence_storage_read on storage.objects for select to authenticated
using (bucket_id='cybertech-evidence' and split_part(name,'/',1)=public.current_org_id()::text);

drop policy if exists evidence_storage_insert on storage.objects;
create policy evidence_storage_insert on storage.objects for insert to authenticated
with check (bucket_id='cybertech-evidence' and split_part(name,'/',1)=public.current_org_id()::text);

drop policy if exists evidence_storage_update on storage.objects;
create policy evidence_storage_update on storage.objects for update to authenticated
using (bucket_id='cybertech-evidence' and split_part(name,'/',1)=public.current_org_id()::text)
with check (bucket_id='cybertech-evidence' and split_part(name,'/',1)=public.current_org_id()::text);

drop policy if exists evidence_storage_delete on storage.objects;
create policy evidence_storage_delete on storage.objects for delete to authenticated
using (bucket_id='cybertech-evidence' and split_part(name,'/',1)=public.current_org_id()::text);

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$ begin new.updated_at=now(); return new; end; $$;

drop trigger if exists touch_remediations on public.remediations;
create trigger touch_remediations before update on public.remediations for each row execute function public.touch_updated_at();

create or replace view public.risk_register as
select r.*, coalesce(r.residual_likelihood,r.likelihood)*coalesce(r.residual_impact,r.impact) as residual_score
from public.risks r where r.organization_id=public.current_org_id();

create or replace view public.compliance_summary as
select c.organization_id,c.framework_id,count(*) controls_total,
count(*) filter (where lower(c.status)='implemented') controls_implemented,
round(avg(coalesce(c.effectiveness,0)),2) average_effectiveness
from public.controls c
where c.organization_id=public.current_org_id()
group by c.organization_id,c.framework_id;
