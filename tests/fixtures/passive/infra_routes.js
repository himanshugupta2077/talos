// Synthetic fixture — infrastructure disclosure observations (no real secrets)
export const routes = [
  "/api/v1/users",
  "/api/v1/orders",
  "/admin/dashboard",
  "/internal/metrics",
  "/debug/pprof",
  "/graphql",
  "/api/v1/users",
  "/api/v1/orders",
];
// Many more API paths to stress aggregation cap
for (let i = 0; i < 80; i++) {
  // eslint-disable-next-line no-unused-vars
  const p = `/api/v1/resource${i}`;
}
const host = "api.internal";
const ip = "10.0.0.42";
const email = "ops@corp-internal.example";
