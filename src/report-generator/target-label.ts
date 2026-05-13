import { ScanTarget } from "../scanner-core/types";

export function targetLabel(target: ScanTarget): string {
  if (target.kind === "url") return target.url.toString();
  if (target.kind === "directory") return target.path;
  return [
    target.url ? target.url.url.toString() : undefined,
    target.directory ? target.directory.path : undefined
  ].filter(Boolean).join(" + ");
}
