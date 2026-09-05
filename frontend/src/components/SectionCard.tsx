/* SPDX-License-Identifier: Apache-2.0 */
import { PropsWithChildren } from "react";

type SectionCardProps = PropsWithChildren<{
  title: string;
  eyebrow?: string;
}>;

export function SectionCard({ title, eyebrow, children }: SectionCardProps) {
  return (
    <section className="section-card">
      <div className="section-card__header">
        {eyebrow ? <span>{eyebrow}</span> : null}
        <h2>{title}</h2>
      </div>
      {children}
    </section>
  );
}
