import js from "@eslint/js";
import tseslint from "typescript-eslint";

const nodeGlobals = {
  process: "readonly",
  Buffer: "readonly",
  console: "readonly",
  fetch: "readonly",
  URL: "readonly",
  TextEncoder: "readonly",
  setTimeout: "readonly",
  clearTimeout: "readonly",
};

export default tseslint.config(
  { ignores: ["**/dist/**", "**/coverage/**", "node_modules/**", "conformance/**"] },
  js.configs.recommended,
  {
    files: ["packages/**/*.ts", "apps/**/*.ts"],
    extends: [...tseslint.configs.strictTypeChecked],
    languageOptions: {
      globals: nodeGlobals,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
  },
  { files: ["**/*.ts", "**/*.mjs"], extends: [tseslint.configs.disableTypeChecked] },
  { files: ["examples/**/*.mjs", "**/*.mjs"], languageOptions: { globals: nodeGlobals } },
);
