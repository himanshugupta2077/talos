package talos.burp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Polls ~/.talos/burp for snapshot changes and merges them into the
 * bound tab. WatchService is skipped — appends on some filesystems
 * do not notify, and a 1s poll is enough for a request table.
 */
final class TalosSnapshotWatcher {
    private static final long INTERVAL_MS = 1_000L;

    private final TalosProjectSession session;
    private volatile boolean running;
    private Thread thread;
    private String lastProjectId = "";
    private long lastSize = -1L;
    private long lastMtime = -1L;
    private long lastDirMtime = -1L;

    TalosSnapshotWatcher(TalosProjectSession session) {
        this.session = session;
    }

    void start() {
        if (running) {
            return;
        }
        running = true;
        Thread next = new Thread(this::loop, "talos-burp-watch");
        next.setDaemon(true);
        next.start();
        this.thread = next;
    }

    void stop() {
        running = false;
        Thread current = this.thread;
        this.thread = null;
        if (current != null) {
            current.interrupt();
        }
    }

    private void loop() {
        while (running) {
            try {
                Thread.sleep(INTERVAL_MS);
            } catch (InterruptedException ignored) {
                return;
            }
            poll();
        }
    }

    private void poll() {
        String projectId = session.boundProjectId();
        Path file = projectId.isBlank() ? null : TalosSnapshots.fileFor(projectId);
        long size = -1L;
        long mtime = -1L;
        if (file != null) {
            try {
                if (Files.isRegularFile(file)) {
                    size = Files.size(file);
                    mtime = Files.getLastModifiedTime(file).toMillis();
                }
            } catch (IOException ignored) {
                return;
            }
        }
        boolean fileChanged = !projectId.equals(lastProjectId)
                || size != lastSize
                || mtime != lastMtime;
        lastProjectId = projectId;
        lastSize = size;
        lastMtime = mtime;
        if (fileChanged && !projectId.isBlank()) {
            session.reloadBound();
        }

        long dirMtime = directoryMtime();
        if (dirMtime != lastDirMtime) {
            lastDirMtime = dirMtime;
            session.notifySnapshotChanged();
        }
    }

    private static long directoryMtime() {
        try {
            Path dir = TalosSnapshots.root();
            if (Files.isDirectory(dir)) {
                return Files.getLastModifiedTime(dir).toMillis();
            }
        } catch (IOException ignored) {
            // picker refresh is best-effort
        }
        return -1L;
    }
}
