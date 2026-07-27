import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        pureblack: "#000000",
        obsidian: "#0B0B0C",
        gold: "#D4AF37",
        "gold-light": "#F3E5AB",
        aegis: {
          void: "#000000",
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
        // Must reference the next/font CSS variables actually loaded in layout.tsx.
        sans: ["var(--font-manrope)", "Manrope", "system-ui", "-apple-system", "sans-serif"],
        display: ["var(--font-cormorant)", "Cormorant Garamond", "Georgia", "serif"],
        mono: ["var(--font-jetbrains)", "JetBrains Mono", "Fira Code", "monospace"],
      },
      boxShadow: {
        brass: "0 0 0 1px rgba(212,175,55,0.18), 0 0 40px rgba(212,175,55,0.15)",
        "brass-strong": "0 0 0 1px rgba(212,175,55,0.30), 0 0 64px rgba(212,175,55,0.22)",
      },
      animation: {
        "spin-slow": "spin 8s linear infinite",
        "glow-border": "borderGlow 3.4s ease-in-out infinite",
        "pulse-ring": "pulseRing 2.4s ease-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;
