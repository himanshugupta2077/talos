import { Navigate, useLocation } from "react-router-dom";
import { TESTING_BASE } from "./registry";

/**
 * Preserve bookmarks to /attack/* after the product surface moved to /testing/*.
 * Backend /api/attack/* is intentionally not rewritten.
 */
export default function LegacyAttackRedirect() {
  const { pathname, search, hash } = useLocation();
  const rest = pathname.replace(/^\/attack/, "") || "";
  return <Navigate to={`${TESTING_BASE}${rest}${search}${hash}`} replace />;
}
