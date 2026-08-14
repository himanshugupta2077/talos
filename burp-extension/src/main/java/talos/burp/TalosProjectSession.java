package talos.burp;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One Talos project per Burp window. Does not guess when unbound.
 * Incoming traffic for a different project never merges into the tree.
 */
final class TalosProjectSession {
    private final TalosPersistence persistence;
    private final TalosStore store;
    private final List<Listener> listeners = new ArrayList<>();
    private final Set<String> ignoredForeign = ConcurrentHashMap.newKeySet();

    private volatile String boundId = "";
    private volatile String boundName = "";
    private volatile String foreignId = "";
    private volatile String foreignName = "";

    TalosProjectSession(TalosPersistence persistence, TalosStore store) {
        this.persistence = persistence;
        this.store = store;
    }

    synchronized void addListener(Listener listener) {
        listeners.add(listener);
    }

    void restore() {
        String id = persistence.loadBoundProjectId();
        String name = persistence.loadBoundProjectName();
        if (id.isBlank()) {
            return;
        }
        bind(id, name, false);
    }

    String boundProjectId() {
        return boundId;
    }

    String boundProjectName() {
        return boundName.isBlank() ? boundId : boundName;
    }

    boolean isBound() {
        return !boundId.isBlank();
    }

    String foreignProjectId() {
        return foreignId;
    }

    String foreignProjectName() {
        return foreignName.isBlank() ? foreignId : foreignName;
    }

    boolean hasForeign() {
        return !foreignId.isBlank();
    }

    synchronized void bind(String projectId, String projectName) {
        bind(projectId, projectName, true);
    }

    private void bind(String projectId, String projectName, boolean persist) {
        String id = TalosSnapshots.safeId(projectId);
        if (id.isEmpty()) {
            return;
        }
        String name = projectName == null || projectName.isBlank()
                ? TalosSnapshots.displayName(id)
                : projectName.trim();
        boolean same = id.equals(boundId);
        boundId = id;
        boundName = name;
        store.setBoundProjectId(id);
        foreignId = "";
        foreignName = "";
        ignoredForeign.remove(id);
        if (persist) {
            persistence.saveBinding(id, name);
        }
        if (!same || store.isEmpty()) {
            store.replaceAll(TalosSnapshots.load(id));
        }
        notifyAllListeners();
    }

    synchronized void unbind() {
        boundId = "";
        boundName = "";
        foreignId = "";
        foreignName = "";
        store.setBoundProjectId("");
        persistence.clearBinding();
        store.replaceAll(List.of());
        notifyAllListeners();
    }

    /**
     * Re-read the bound snapshot and merge. Does not fire bindingChanged
     * (that wipes the request table). Used by Refresh and auto-refresh.
     */
    void reloadBound() {
        String id;
        synchronized (this) {
            id = boundId;
        }
        if (id.isBlank()) {
            return;
        }
        store.mergeFrom(TalosSnapshots.load(id));
    }

    void notifySnapshotChanged() {
        fire(Listener::snapshotChanged);
    }

    /**
     * @return true when the row may be added to the current tree.
     */
    boolean accept(TalosTrace trace) {
        String incoming = trace.projectId == null ? "" : trace.projectId.trim();
        if (boundId.isBlank()) {
            if (!incoming.isBlank() && !ignoredForeign.contains(incoming)) {
                setForeign(incoming, trace.projectName);
            }
            return false;
        }
        if (incoming.isBlank() || incoming.equals(boundId)) {
            return true;
        }
        if (!ignoredForeign.contains(incoming)) {
            setForeign(incoming, trace.projectName);
        }
        return false;
    }

    synchronized void ignoreForeign() {
        if (!foreignId.isBlank()) {
            ignoredForeign.add(foreignId);
        }
        foreignId = "";
        foreignName = "";
        notifyForeign();
    }

    void switchToForeign() {
        String id;
        String name;
        synchronized (this) {
            id = foreignId;
            name = foreignName;
        }
        if (id.isBlank()) {
            return;
        }
        bind(id, name, true);
    }

    private void setForeign(String projectId, String projectName) {
        String id = TalosSnapshots.safeId(projectId);
        if (id.isEmpty()) {
            return;
        }
        String name = projectName == null || projectName.isBlank()
                ? TalosSnapshots.displayName(id)
                : projectName.trim();
        boolean changed;
        synchronized (this) {
            changed = !id.equals(foreignId) || !name.equals(foreignName);
            foreignId = id;
            foreignName = name;
        }
        if (changed) {
            notifyForeign();
        }
    }

    private void notifyAllListeners() {
        notifyBinding();
        notifyForeign();
    }

    private void notifyBinding() {
        fire(Listener::bindingChanged);
    }

    private void notifyForeign() {
        fire(Listener::foreignChanged);
    }

    private void fire(java.util.function.Consumer<Listener> action) {
        List<Listener> copy;
        synchronized (this) {
            copy = List.copyOf(listeners);
        }
        Runnable run = () -> {
            for (Listener listener : copy) {
                action.accept(listener);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            run.run();
        } else {
            SwingUtilities.invokeLater(run);
        }
    }

    interface Listener {
        void bindingChanged();

        void foreignChanged();

        default void snapshotChanged() {
        }
    }
}
