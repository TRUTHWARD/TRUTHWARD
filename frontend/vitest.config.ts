/* SPDX-License-Identifier: Apache-2.0 */
import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => {
  const isOss = loadEnv(mode, ".", "").VITE_PRODUCT_PROFILE?.trim().toLowerCase() === "oss";
  return {
    plugins: [react()],
    resolve: {
      alias: {
        "@truthward/enterprise-pages": fileURLToPath(
          new URL(isOss ? "./src/composition/enterprisePages.oss.tsx" : "../enterprise/frontend/src/enterprisePages.ts", import.meta.url),
        ),
        "@truthward/gate-policies-page": fileURLToPath(
          new URL(isOss ? "./src/pages/GatePoliciesPage.oss.tsx" : "./src/pages/GatePoliciesPage.tsx", import.meta.url),
        ),
      },
    },
    test: {
      // Full-product contracts remain runnable, but never enter the OSS test composition.
      include: isOss
        ? ["tests/{Community*,Oss*,ChangeSetsPage,ImpactAnalysisPage,SelectiveReplayPlansPage,HeaderPresentation,LocaleQuality,PresentationLabels}.test.{ts,tsx}"]
        : ["tests/**/*.test.{ts,tsx}"],
      environment: "jsdom",
      globals: true,
      setupFiles: ["./tests/setup.ts"],
      restoreMocks: true,
      clearMocks: true,
      coverage: {
        provider: "v8",
        reporter: ["text", "html", "cobertura"],
        reportsDirectory: "../coverage/frontend",
        include: ["src/**/*.{ts,tsx}"],
        thresholds: {
          lines: 80,
          statements: 80,
          functions: 80,
          branches: 80,
        },
      },
    },
  };
});
