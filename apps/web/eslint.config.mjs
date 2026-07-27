import { dirname } from "path";
import { fileURLToPath } from "url";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({
  baseDirectory: __dirname,
});

const eslintConfig = [
  {
    ignores: [".next/**", "node_modules/**", "out/**", "build/**"],
  },
  ...compat.extends("next/core-web-vitals"),
  {
    rules: {
      // Cosmetic: literal apostrophes/quotes in JSX text are safe and readable.
      // Meaningful Next/react-hooks rules stay on.
      "react/no-unescaped-entities": "off",
    },
  },
];

export default eslintConfig;
