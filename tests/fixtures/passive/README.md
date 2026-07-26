# Passive Source Intelligence fixtures

Synthetic source bodies for detector / worker tests only.

**Never** commit live credentials. Use AWS/GitHub *example* shapes and
obviously fake material:

| File | Purpose |
|------|---------|
| `aws_key.js` | AWS AKIA true positive (synthetic, not EXAMPLE) |
| `github_pat.js` | GitHub `ghp_` PAT shape |
| `stripe_key.json` | Placeholder; Stripe body assembled in detector tests |
| `google_api.js` | Google `AIza` API key shape |
| `contextual_secrets.js` | Assignment true/false positives for Phase 6 |
| `encoded_password.js` | Base64(`password=SuperSecret123`) for Phase 7 |
| `pem_key.js` | Multi-line PEM begin/end block |
| `noise_uuids.js` | UUIDs / random hex → zero provider hits |
| `aws_in_sourcemap.map` | sourcesContent with AWS key (Phase 10) |
| `map_without_sourcescontent.map` | Valid map, no sourcesContent |
| `inline_aws.html` | Inline script + `__NEXT_DATA__` bootstrap (Phase 11) |
| `infra_routes.js` | Internal host/IP + API routes (Phase 12) |
| `jwt_and_conn.js` | Compact JWT + postgres URI credentials |
