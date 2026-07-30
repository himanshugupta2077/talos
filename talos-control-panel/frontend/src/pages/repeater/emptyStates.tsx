import { Link } from "react-router-dom";

export function NoProjectEmpty() {
  return (
    <div className="panel p-8 text-center text-base-content/60">
      Select a project to use the Repeater — or{" "}
      <Link to="/projects" className="link link-primary">
        create one
      </Link>
      .
    </div>
  );
}

export function NoTabsEmpty({
  onOpenFlow,
}: {
  onOpenFlow: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-16 px-6 text-center">
      <div className="text-lg font-semibold">Repeater</div>
      <p className="text-sm text-base-content/60 max-w-md">
        Open a captured flow to edit and send. Tabs stick in the project archive
        (survive refresh). Draft bodies stay local until Send; every send creates
        a new flow with full lineage (captures stay immutable).
      </p>
      <p className="text-xs text-base-content/50 max-w-md">
        Tip: from{" "}
        <Link to="/flows" className="link">
          Flows
        </Link>{" "}
        or Flow Detail use <strong>Send to Repeater</strong>, or open by flow UUID.
      </p>
      <button type="button" className="btn btn-sm btn-primary" onClick={onOpenFlow}>
        Open flow…
      </button>
    </div>
  );
}

export function HistoryEmpty() {
  return (
    <div className="text-xs text-base-content/50 p-3">
      No sends under this root yet. Edit the request and press <strong>Send</strong>{" "}
      (<kbd className="kbd kbd-xs">Ctrl</kbd>+
      <kbd className="kbd kbd-xs">Enter</kbd>).
    </div>
  );
}
