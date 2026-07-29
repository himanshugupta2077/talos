import { Navigate, useLocation } from "react-router-dom";
import { IV_BASE } from "./registry";

/**
 * Preserve bookmarks to /input-validation/* after nesting under Testing.
 */
export default function LegacyIvRedirect() {
  const { pathname, search, hash } = useLocation();
  const rest = pathname.replace(/^\/input-validation/, "") || "";
  return <Navigate to={`${IV_BASE}${rest}${search}${hash}`} replace />;
}
