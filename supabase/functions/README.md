# CyberTech 360 Edge Functions

V2.2 reserves the server-side boundary for privileged operations.

Planned functions:
- health
- bootstrap-organization
- evidence-sign-url
- audit-event
- compliance-score
- report-generate
- notification-dispatch
- ai-grc-copilot

Rules:
- Validate the authenticated user and organization server-side.
- Never expose the Supabase service-role key to browser code.
- Apply least privilege to every function.
- Return only tenant-authorized data.
