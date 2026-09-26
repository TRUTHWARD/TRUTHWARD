/* SPDX-License-Identifier: Apache-2.0 */
import { Component, type ReactNode } from "react";

import { type Locale, t } from "../i18n";

type PageErrorBoundaryProps = {
  children: ReactNode;
  locale: Locale;
};

type PageErrorBoundaryState = {
  failed: boolean;
};

export class PageErrorBoundary extends Component<PageErrorBoundaryProps, PageErrorBoundaryState> {
  state: PageErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): PageErrorBoundaryState {
    return { failed: true };
  }

  render() {
    if (this.state.failed) {
      return (
        <div className="error-banner" role="alert">
          <strong>{t(this.props.locale, "pageRenderFailed")}</strong>
          <p>{t(this.props.locale, "pageRenderFailedHelp")}</p>
        </div>
      );
    }
    return this.props.children;
  }
}
