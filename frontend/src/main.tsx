/* SPDX-License-Identifier: Apache-2.0 */
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { CommunityAuthBoundary } from "./components/CommunityAuthBoundary";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <CommunityAuthBoundary><App /></CommunityAuthBoundary>
  </React.StrictMode>,
);
