/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
    plugins: [react()],
    server: {
        // Bind IPv4 explicitly so 127.0.0.1 health checks / openers work
        // (plain "localhost" can resolve to IPv6-only on some systems).
        host: "127.0.0.1",
        port: 5173,
        strictPort: true,
    },
    // Vitest config (devDependency); ignored by production vite build.
    test: {
        environment: "jsdom",
        globals: true,
        setupFiles: ["./src/test/setup.ts"],
    },
});
