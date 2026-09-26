/* SPDX-License-Identifier: Apache-2.0 */
export function readRouteSelection(name: string) {
  if (typeof window === "undefined") return null;
  const value = new URLSearchParams(window.location.search).get(name)?.trim() ?? "";
  const hasControlCharacter = [...value].some((character) => character.charCodeAt(0) < 32);
  return value && value.length <= 255 && !hasControlCharacter ? value : null;
}
