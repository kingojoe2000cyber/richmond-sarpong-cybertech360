-- CyberTech 360 V2.5 Phase 2
-- Operational audit trail trigger for live CRUD/SOC workflows.
-- Run after V2.4.2 in the CyberTech 360 Supabase SQL Editor.

create or replace function public.ct360_audit_row_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  row_data jsonb;
  org_id uuid;
  object_id text;
  summary text;
begin
  row_data := case when TG_OP = 'DELETE' then to_jsonb(OLD) else to_jsonb(NEW) end;
  org_id := nullif(row_data->>'organization_id','')::uuid;
  object_id := coalesce(row_data->>'id', row_data->>'risk_code', row_data->>'control_code', row_data->>'incident_code', row_data->>'evidence_code', row_data->>'cve', '');
  summary := coalesce(
    row_data->>'title',
    row_data->>'name',
    row_data->>'message',
    row_data->>'summary',
    TG_OP || ' on ' || TG_TABLE_NAME
  );

  if org_id is not null then
    insert into public.audit_log (
      organization_id,
      actor_id,
      action,
      object_type,
      object_id,
      summary,
      created_at
    )
    values (
      org_id,
      auth.uid(),
      lower(TG_OP),
      TG_TABLE_NAME,
      object_id,
      left(summary, 500),
      now()
    );
  end if;

  return case when TG_OP = 'DELETE' then OLD else NEW end;
end;
$$;

revoke all on function public.ct360_audit_row_change() from public, anon, authenticated;

do $$
declare
  t text;
begin
  foreach t in array array[
    'risks',
    'controls',
    'evidence',
    'vulnerabilities',
    'incidents',
    'siem_events',
    'remediations'
  ] loop
    execute format('drop trigger if exists ct360_audit_row_change on public.%I', t);
    execute format(
      'create trigger ct360_audit_row_change
       after insert or update or delete on public.%I
       for each row execute function public.ct360_audit_row_change()',
      t
    );
  end loop;
end
$$;

create index if not exists idx_audit_log_org_created
  on public.audit_log(organization_id, created_at desc);

create index if not exists idx_audit_log_object
  on public.audit_log(object_type, object_id);

-- Validation
select
  tgname as trigger_name,
  tgrelid::regclass as table_name
from pg_trigger
where tgname = 'ct360_audit_row_change'
order by tgrelid::regclass::text;

select
  count(*) as audit_trigger_count
from pg_trigger
where tgname = 'ct360_audit_row_change';
