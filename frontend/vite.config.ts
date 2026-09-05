/* SPDX-License-Identifier: Apache-2.0 */
import { fileURLToPath, URL } from "node:url";

import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

const apiProxyTarget = (process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8000").trim().replace(/\/+$/, "");

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const isOss = env.VITE_PRODUCT_PROFILE?.trim().toLowerCase() === "oss";
  const enterprisePages = isOss
    ? new URL("./src/composition/enterprisePages.oss.tsx", import.meta.url)
    : new URL("../enterprise/frontend/src/enterprisePages.ts", import.meta.url);
  const gatePoliciesPage = isOss
    ? new URL("./src/pages/GatePoliciesPage.oss.tsx", import.meta.url)
    : new URL("./src/pages/GatePoliciesPage.tsx", import.meta.url);

  return {
    plugins: [react()],
    resolve: {
      alias: {
        "@truthward/enterprise-pages": fileURLToPath(enterprisePages),
        "@truthward/gate-policies-page": fileURLToPath(gatePoliciesPage),
      },
    },
    server: {
      host: "0.0.0.0",
      port: 5173,
      proxy: {
        "/api": {
          target: apiProxyTarget,
          changeOrigin: true,
          secure: false,
        },
      },
    },
  };
});
