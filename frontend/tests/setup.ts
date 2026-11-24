/* SPDX-License-Identifier: Apache-2.0 */
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

import { usePlatformStore } from "../src/store/platform";

const initialPlatformState = usePlatformStore.getInitialState();

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  usePlatformStore.setState(initialPlatformState, true);
});
