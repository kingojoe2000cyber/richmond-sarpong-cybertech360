# CyberTech 360 V2 Architecture

CyberTech 360 V2 is an enterprise cybersecurity GRC and security-operations platform foundation. The public GitHub Pages build is explicitly demo mode; production requires an authenticated backend.

## Production target
- Frontend: React + TypeScript
- API: FastAPI or Node.js
- Database: PostgreSQL
- Identity: Supabase Auth/OIDC + MFA
- Authorization: RBAC + tenant-aware Row Level Security
- Evidence: private encrypted object storage
- Jobs: Redis/queue worker
- AI: retrieval-grounded GRC copilot
- Security telemetry: SIEM/SOC integrations
- CI/CD: GitHub Actions with lint, tests, SAST, dependency and DAST gates

## Domains
Executive Command Center, Risk Management, Control Library, Compliance, Evidence, Audit, Incident Management, Assets, Vulnerabilities, Third-Party Risk, Business Continuity/DR, PCI DSS, Reporting and AI GRC Copilot.

## Security principles
Least privilege, deny-by-default authorization, tenant isolation, MFA for privileged users, server-side validation, immutable audit events, encryption in transit/at rest, no secrets in frontend code, evidence SHA-256 integrity, retention controls and tested recovery.

## Request flow
Browser -> HTTPS -> Auth -> API authorization -> PostgreSQL RLS -> domain service -> audit event.

## Demo boundary
The public frontend uses synthetic records and local demo persistence. It must not be treated as a live security telemetry or compliance system.
