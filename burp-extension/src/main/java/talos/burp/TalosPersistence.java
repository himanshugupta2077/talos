package talos.burp;

import burp.api.montoya.persistence.PersistedObject;

/**
 * Burp-project binding only. Tree rows live in ~/.talos/burp/&lt;id&gt;.jsonl.
 *
 * Professional saved projects remember which Talos project this window
 * is bound to. Community / temp projects lose the binding on quit —
 * they must pick again. Never stores a global "last project".
 */
final class TalosPersistence {
    private static final String BOUND_ID = "talos.boundProjectId";
    private static final String BOUND_NAME = "talos.boundProjectName";

    private final PersistedObject root;

    TalosPersistence(PersistedObject root) {
        this.root = root;
    }

    String loadBoundProjectId() {
        return nz(root.getString(BOUND_ID));
    }

    String loadBoundProjectName() {
        return nz(root.getString(BOUND_NAME));
    }

    void saveBinding(String projectId, String projectName) {
        root.setString(BOUND_ID, nz(projectId));
        root.setString(BOUND_NAME, nz(projectName));
    }

    void clearBinding() {
        root.setString(BOUND_ID, "");
        root.setString(BOUND_NAME, "");
    }

    private static String nz(String value) {
        return value == null ? "" : value.trim();
    }
}
