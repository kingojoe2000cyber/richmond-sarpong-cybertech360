create extension if not exists pgcrypto;

create table if not exists organizations(id uuid primary key default gen_random_uuid(),name text not null,slug text unique not null,created_at timestamptz default now());
create table if not exists profiles(id uuid primary key references auth.users(id) on delete cascade,organization_id uuid not null references organizations(id) on delete cascade,full_name text not null,role text not null check(role in ('super_admin','grc_manager','security_manager','risk_manager','compliance_officer','auditor','soc_analyst','it_admin','executive','viewer')),created_at timestamptz default now());
create table if not exists frameworks(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,name text not null,version text not null,active boolean default true);
create table if not exists controls(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,framework_id uuid references frameworks(id) on delete set null,control_code text not null,title text not null,description text,status text default 'not_assessed',effectiveness numeric(5,2) default 0,unique(organization_id,control_code));
create table if not exists risks(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,risk_code text not null,title text not null,description text,category text,likelihood int check(likelihood between 1 and 5),impact int check(impact between 1 and 5),inherent_score int generated always as (coalesce(likelihood,0)*coalesce(impact,0)) stored,residual_likelihood int check(residual_likelihood between 1 and 5),residual_impact int check(residual_impact between 1 and 5),treatment text,owner_id uuid references profiles(id),due_date date,status text default 'open',created_at timestamptz default now());
create table if not exists evidence(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,evidence_code text not null,file_name text not null,object_path text not null,sha256 text,control_id uuid references controls(id) on delete set null,owner_id uuid references profiles(id) on delete set null,status text default 'pending_review',review_date date,created_at timestamptz default now());
create table if not exists incidents(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,incident_code text not null,title text not null,description text,severity text not null check(severity in ('Critical','High','Medium','Low')),status text default 'Open',owner_id uuid references profiles(id) on delete set null,opened_at timestamptz default now(),resolved_at timestamptz);
create table if not exists assets(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,asset_code text not null,name text not null,asset_type text not null,criticality text,owner_id uuid references profiles(id) on delete set null,environment text,status text default 'active');
create table if not exists vulnerabilities(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,cve text,asset_id uuid references assets(id) on delete cascade,cvss numeric(3,1),severity text,status text default 'open',due_date date);
create table if not exists vendors(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,vendor_code text not null,name text not null,tier text,risk_score numeric(5,2),status text);
create table if not exists audits(id uuid primary key default gen_random_uuid(),organization_id uuid not null references organizations(id) on delete cascade,audit_code text not null,name text not null,framework_id uuid references frameworks(id) on delete set null,status text,progress numeric(5,2) default 0,due_date date);
create table if not exists audit_log(id bigint generated always as identity primary key,organization_id uuid not null references organizations(id) on delete cascade,actor_id uuid references auth.users(id) on delete set null,action text not null,object_type text not null,object_id text,before_json jsonb,after_json jsonb,ip_address inet,created_at timestamptz default now());

alter table profiles enable row level security;
alter table frameworks enable row level security;
alter table controls enable row level security;
alter table risks enable row level security;
alter table evidence enable row level security;
alter table incidents enable row level security;
alter table assets enable row level security;
alter table vulnerabilities enable row level security;
alter table vendors enable row level security;
alter table audits enable row level security;
alter table audit_log enable row level security;

-- Add organization-aware RLS policies before production data is enabled.
