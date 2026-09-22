# V2.2 Security Test Plan

## Tenant isolation
- User A cannot read Organization B records.
- User A cannot insert a record with Organization B's ID.
- User A cannot access Organization B evidence objects.
- User A cannot modify another organization's remediation.

## RBAC
- Viewer is read-only.
- Auditor can review evidence and audits but cannot administer users.
- Risk manager can manage risk records.
- Compliance officer can manage assessments and evidence workflows.
- Super administrator can administer tenant configuration.

## Audit
- INSERT/UPDATE/DELETE on protected domain records produces an audit event.
- Browser sessions cannot UPDATE or DELETE audit history.
- Audit events contain actor, action, object and before/after state.

## Evidence
- Bucket is private.
- Object paths begin with the organization UUID.
- Cross-tenant signed URLs are denied.
- SHA-256 is stored after successful upload verification.

## Secrets
- No service-role credential exists in frontend code.
- Production secrets are supplied through deployment environment variables.
