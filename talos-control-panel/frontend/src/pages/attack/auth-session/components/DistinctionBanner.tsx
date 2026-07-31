import { Link } from "react-router-dom";

/**
 * Homonym / module-boundary banner — Auth-Session is not Unauth, BAC,
 * Auth page config, or classic Authentication Bypass.
 */
export default function DistinctionBanner() {
  return (
    <div className="alert alert-info text-xs py-2 mb-4">
      <span>
        <strong>Not Unauth</strong> (strip auth). <strong>Not BAC</strong>{" "}
        (other-role session). <strong>Not Auth page</strong> (config / role
        sessions). <strong>Not classic Authentication Bypass</strong> (
        <span className="mono">auth test</span> / BYPASS). This module tests
        whether <em>mutated</em> tokens are still accepted.{" "}
        <Link className="link link-primary" to="/testing/unauth">
          Unauth
        </Link>
        {" · "}
        <Link className="link link-primary" to="/testing/bac">
          BAC
        </Link>
        {" · "}
        <Link className="link link-primary" to="/auth">
          Auth config
        </Link>
      </span>
    </div>
  );
}
