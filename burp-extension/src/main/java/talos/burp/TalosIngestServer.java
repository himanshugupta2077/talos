package talos.burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Localhost ingest so Talos can hand the extension a trace without
 * putting X-Talos-* on the proxied request.
 *
 * Implemented with ServerSocket only — Burp's JRE does not expose
 * com.sun.net.httpserver.
 */
final class TalosIngestServer {
    static final int DEFAULT_PORT = 17384;
    static final int PORT_LIMIT = 17389;

    private final TalosIngestQueue queue;
    private final LogSink log;
    private volatile ServerSocket server;
    private Thread acceptThread;
    private int boundPort = -1;

    TalosIngestServer(TalosIngestQueue queue, LogSink log) {
        this.queue = queue;
        this.log = log;
    }

    int start() {
        IOException last = null;
        for (int port = DEFAULT_PORT; port <= PORT_LIMIT; port++) {
            try {
                ServerSocket socket = new ServerSocket(port, 16, InetAddress.getByName("127.0.0.1"));
                socket.setReuseAddress(true);
                this.server = socket;
                this.boundPort = port;
                Thread thread = new Thread(this::acceptLoop, "talos-burp-ingest");
                thread.setDaemon(true);
                thread.start();
                this.acceptThread = thread;
                writePortFile(port);
                log.info("Talos ingest listening on http://127.0.0.1:" + port
                        + " — traces arrive out of band, not as X-Talos-* headers.");
                return port;
            } catch (IOException exc) {
                last = exc;
            }
        }
        log.info("Talos ingest failed to bind 127.0.0.1:" + DEFAULT_PORT
                + "-" + PORT_LIMIT
                + (last == null ? "" : " (" + last.getMessage() + ")")
                + ". Falling back to X-Talos-* headers.");
        return -1;
    }

    void stop() {
        ServerSocket socket = this.server;
        this.server = null;
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // shutting down
            }
        }
        Thread thread = this.acceptThread;
        this.acceptThread = null;
        if (thread != null) {
            thread.interrupt();
        }
        boundPort = -1;
    }

    int port() {
        return boundPort;
    }

    private void acceptLoop() {
        ServerSocket listener = this.server;
        if (listener == null) {
            return;
        }
        while (!listener.isClosed() && this.server == listener) {
            try {
                Socket client = listener.accept();
                client.setSoTimeout(2_000);
                handle(client);
            } catch (SocketTimeoutException ignored) {
                // keep listening
            } catch (IOException exc) {
                if (this.server == listener && !listener.isClosed()) {
                    log.info("Talos ingest accept error: " + exc.getMessage());
                }
            }
        }
    }

    private void handle(Socket client) {
        try (Socket socket = client;
             InputStream in = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {
            ParsedRequest req = readRequest(in);
            if (req == null) {
                writeResponse(out, 400, "text/plain", "bad request");
                return;
            }
            if ("GET".equals(req.method) && "/health".equals(req.path)) {
                writeResponse(out, 200, "application/json",
                        "{\"ok\":true,\"service\":\"talos-burp\"}");
                return;
            }
            if ("POST".equals(req.method) && "/ingest".equals(req.path)) {
                queue.offer(req.body);
                writeResponse(out, 204, "text/plain", "");
                return;
            }
            writeResponse(out, 404, "text/plain", "not found");
        } catch (IOException ignored) {
            // client gone
        }
    }

    private static ParsedRequest readRequest(InputStream in) throws IOException {
        String start = readLine(in);
        if (start == null || start.isBlank()) {
            return null;
        }
        String[] parts = start.split(" ", 3);
        if (parts.length < 2) {
            return null;
        }
        String method = parts[0].trim().toUpperCase(Locale.ROOT);
        String path = parts[1].trim();
        int q = path.indexOf('?');
        if (q >= 0) {
            path = path.substring(0, q);
        }
        int contentLength = 0;
        while (true) {
            String line = readLine(in);
            if (line == null || line.isEmpty()) {
                break;
            }
            int colon = line.indexOf(':');
            if (colon < 0) {
                continue;
            }
            String name = line.substring(0, colon).trim();
            if (name.equalsIgnoreCase("Content-Length")) {
                try {
                    contentLength = Integer.parseInt(line.substring(colon + 1).trim());
                } catch (NumberFormatException ignored) {
                    contentLength = 0;
                }
            }
        }
        if (contentLength < 0 || contentLength > 64 * 1024) {
            return new ParsedRequest(method, path, "");
        }
        byte[] buf = in.readNBytes(contentLength);
        String body = new String(buf, StandardCharsets.UTF_8);
        return new ParsedRequest(method, path, body);
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int prev = -1;
        while (true) {
            int ch = in.read();
            if (ch < 0) {
                return buf.size() == 0 ? null : buf.toString(StandardCharsets.US_ASCII);
            }
            if (ch == '\n') {
                break;
            }
            if (prev == '\r' && ch != '\n') {
                buf.write(prev);
            }
            if (ch != '\r') {
                buf.write(ch);
            }
            prev = ch;
            if (buf.size() > 8 * 1024) {
                break;
            }
        }
        return buf.toString(StandardCharsets.US_ASCII);
    }

    private static void writeResponse(OutputStream out, int status, String type, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        String reason = switch (status) {
            case 200 -> "OK";
            case 204 -> "No Content";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            default -> "OK";
        };
        String headers = "HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: " + type + "\r\n"
                + "Content-Length: " + bytes.length + "\r\n"
                + "Connection: close\r\n"
                + "\r\n";
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        if (bytes.length > 0) {
            out.write(bytes);
        }
        out.flush();
    }

    static Path portFile() {
        return Path.of(System.getProperty("user.home"), ".talos", "burp-ingest.port");
    }

    private static void writePortFile(int port) {
        try {
            Path file = portFile();
            Files.createDirectories(file.getParent());
            Files.writeString(file, Integer.toString(port), StandardCharsets.UTF_8);
        } catch (IOException ignored) {
            // Discovery falls back to the default port.
        }
    }

    interface LogSink {
        void info(String message);
    }

    private static final class ParsedRequest {
        final String method;
        final String path;
        final String body;

        ParsedRequest(String method, String path, String body) {
            this.method = method;
            this.path = path;
            this.body = body;
        }
    }
}
