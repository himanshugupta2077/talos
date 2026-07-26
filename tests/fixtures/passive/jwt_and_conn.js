// Synthetic JWT + connection string fixtures (not live credentials).
// Compact JWT shape only — not a signed real token (fake signature segment).
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0YWxvcy10ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.TALOS_FAKE_SIGNATURE_SEGMENT00";
const dbUrl = "postgres://appuser:s3cretPassw0rd@db.internal:5432/app";
export { token, dbUrl };
