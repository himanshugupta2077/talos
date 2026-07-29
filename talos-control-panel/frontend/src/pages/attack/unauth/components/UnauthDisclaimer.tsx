/** Active-risk blurb for Unauthenticated Execution. */

export default function UnauthDisclaimer() {
  return (
    <div className="alert alert-warning text-xs py-2 mb-4">
      <div>
        <span className="font-medium">Active attack.</span> Each job strips
        configured authentication, applies a technique (and optional request
        mutation), then replays against the live target. Prefer narrow
        techniques when exploring; use Endpoint Policy to exclude logout /
        dangerous paths.
      </div>
    </div>
  );
}
