# Supabase production setup

1. Create a Supabase project.
2. Run schema.sql.
3. Enable email/OIDC authentication and MFA.
4. Seed an organization and controlled admin profile.
5. Add organization-aware RLS policies before production use.
6. Use a private storage bucket for evidence.
7. Never expose the service-role key in browser code.

Only the public Supabase URL and anon key belong in a browser build.
