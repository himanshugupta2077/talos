import { Navigate, useLocation } from "react-router-dom";
import { SECRETS_BASE } from "./registry";

/**
 * Preserve bookmarks to /secret-detection/* after nesting under Testing.
 */
export default function LegacySecretRedirect() {
  const { pathname, search, hash } = useLocation();
  const rest = pathname.replace(/^\/secret-detection/, "") || "";
  return <Navigate to={`${SECRETS_BASE}${rest}${search}${hash}`} replace />;
}
