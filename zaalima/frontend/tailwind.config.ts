import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#080D19",
          sidebar: "#0B1220",
          card: "#111B2E",
          cardHover: "#15223A",
          border: "#263449",
          borderSubtle: "#1C2738",
          primary: "#3B82F6",
          primaryHover: "#2563EB",
          critical: "#EF4444",
          warning: "#F59E0B",
          success: "#10B981",
          text: "#F8FAFC",
          muted: "#94A3B8",
          subtle: "#64748B",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 4px 20px -2px rgba(0, 0, 0, 0.45)",
        glowBlue: "0 0 25px -5px rgba(59, 130, 246, 0.3)",
        glowRed: "0 0 25px -5px rgba(239, 68, 68, 0.3)",
        glowGreen: "0 0 25px -5px rgba(16, 185, 129, 0.3)",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "spin-slow": "spin 8s linear infinite",
      },
    },
  },
  plugins: [],
};
export default config;
