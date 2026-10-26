import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@shopify/ui-extensions-react/admin": fileURLToPath(new URL("./test/fixtures/shopify-admin.jsx", import.meta.url)),
    },
  },
});
