import { ScanTarget } from "../scanner-core/types";

export function targetLabel(target: ScanTarget): string {
  if (target.kind === "url") return target.url.toString();
  if (target.kind === "directory") return target.path;
  if (target.kind === "api-spec") return target.path;
  return [
    target.url ? target.url.url.toString() : undefined,
    target.directory ? target.directory.path : undefined,
    target.apiSpec ? target.apiSpec.path : undefined
  ].filter(Boolean).join(" + ");
}
