# Richmond Sarpong CyberTech 360 — Version 2

Version 2 upgrades the current static GitHub Pages dashboard into a multi-tenant Cybersecurity GRC Management Platform.

## Target architecture

- Frontend: current CyberTech 360 UI, progressively upgraded to API-driven screens
- Backend API: FastAPI
- Database: PostgreSQL
- ORM: SQLAlchemy 2.x
- Authentication: JWT-based login foundation with RBAC
- Deployment: Docker-ready backend; V1 static GitHub Pages remains untouched on `main`

## Core modules

1. Organizations / multi-client tenancy
2. Users, roles and permissions
3. ISO 27001, NIST CSF, CIS Controls and COBIT framework library
4. Compliance assessments and control testing
5. Enterprise risk register and heat maps
6. Incident management
7. Audit management
8. Evidence register / uploads
9. BIA, BCP and Disaster Recovery
10. Vendor / third-party risk
11. Reports and executive dashboards
12. Activity and audit logs

## Delivery phases

### Phase 1 — Platform foundation
- PostgreSQL service
- FastAPI application
- configuration management
- database session layer
- health API
- organization and user data model foundation

### Phase 2 — Identity and tenancy
- login
- password hashing
- JWT access tokens
- RBAC
- organization-scoped data access

### Phase 3 — GRC modules
- risks
- controls
- assessments
- incidents
- audits
- evidence
- vendors
- BIA/BCP/DR

### Phase 4 — Dashboard integration
- API-backed executive metrics
- risk heat map
- compliance charts
- audit and incident trends
- board reporting

### Phase 5 — Production deployment
- managed PostgreSQL
- backend hosting
- environment secrets
- domain / HTTPS
- backups
- observability
- release process

## Branch strategy

- `main` = currently live Version 1
- `version-2` = Version 2 development

Do not merge `version-2` into `main` until the backend and upgraded frontend are tested.
