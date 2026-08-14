# Richmond Sarpong CyberTech 360

A professional, responsive cybersecurity governance and operations dashboard inspired by the cybersecurity template catalogue supplied by the project owner.

## Included modules

- Information Security
- Cloud Security
- Security Management
- Network Security
- Application Security
- Disaster Recovery
- Incident Management
- Problem Management
- Reports & Analytics
- Settings

## Dashboard capabilities

- Executive cybersecurity command center
- Security posture KPIs
- Risk distribution and enterprise risk heat map
- ISO/IEC 27001, NIST CSF, CIS Controls and COBIT compliance progress
- Security event trend visualization
- Incident register with local browser persistence
- Create incident modal and CSV export
- Cybersecurity template/document library mapped to the supplied image
- Responsive desktop/mobile layout
- Dark and light themes
- GitHub Pages deployment workflow
- No build framework or external JavaScript dependency required

## Run locally

Because this is a static web application, you can open `index.html` directly in a browser. For a local web server, run one of the following from the project folder:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080`.

## Deploy to GitHub Pages

1. Create a new GitHub repository, for example `richmond-sarpong-cybertech360`.
2. Upload/push all files in this project to the repository's `main` branch.
3. In GitHub, open **Settings → Pages**.
4. Under **Build and deployment**, select **GitHub Actions**.
5. The included `.github/workflows/deploy-pages.yml` workflow will publish the dashboard automatically after each push to `main`.

## Git command example

```bash
git init
git add .
git commit -m "Initial CyberTech 360 dashboard"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/richmond-sarpong-cybertech360.git
git push -u origin main
```

## Important production note

The current version is a polished front-end demonstrator. Incident records are stored in browser `localStorage`. For a production multi-user cybersecurity GRC platform, connect the interface to an authenticated backend such as PostgreSQL + FastAPI/Django/Node.js, add RBAC, audit logging, encrypted evidence storage, SSO/MFA, API security, backups and server-side reporting.

## Project structure

```text
richmond-sarpong-cybertech360/
├── index.html
├── styles.css
├── app.js
├── README.md
├── assets/
│   └── favicon.svg
└── .github/
    └── workflows/
        └── deploy-pages.yml
```
