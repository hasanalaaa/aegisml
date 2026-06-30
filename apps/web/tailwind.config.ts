import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        aegis: {
          bg: "#0B0B0C",
          surface: "#121214",
          elevated: "#18181B",
          card: "#121214",
          border: "#1F1F23",
          brass: "#D4AF37",
          brassLight: "#E8C84A",
          gold: "#D4AF37",
          silver: "#A8A8B3",
          text: "#EFEFEF",
          muted: "#9090A8",
          clean: "#22C55E",
          suspicious: "#F59E0B",
          critical: "#DC2626",
        },
      },
      fontFamily: {
        sans: ["var(--font-inter)", "Inter", "system-ui", "-apple-system", "sans-serif"],
        display: ["var(--font-sora)", "Sora", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "Fira Code", "monospace"],
      },
      boxShadow: {
        brass: "0 0 0 1px rgba(212,175,55,0.18), 0 0 40px rgba(212,175,55,0.15)",
      },
    },
  },
  plugins: [],
};

export default config;
