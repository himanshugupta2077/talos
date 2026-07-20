/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [require("daisyui")],
  daisyui: {
    // Prebuilt daisyUI themes only — no custom palette, just light/dark switching.
    themes: ["light", "dark"],
    darkTheme: "dark",
  },
};
