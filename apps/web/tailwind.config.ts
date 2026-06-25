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
          bg: "#0A0A0F",
          card: "#12121E",
          gold: "#C9A84C",
          text: "#F0F0F8",
          muted: "#A8A8C4",
          clean: "#2ECC71",
          suspicious: "#E67E22",
          critical: "#E74C3C",
        },
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;
