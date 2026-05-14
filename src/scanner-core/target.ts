import fs from "node:fs";
import path from "node:path";
import { ApiSpecTarget, DirectoryTarget, ScanTarget, UrlTarget } from "./types";

export interface ValidateTargetOptions {
  confirmAuthorization: boolean;
}

export function validateTarget(rawTarget: string, options: ValidateTargetOptions): ScanTarget {
  if (!rawTarget || rawTarget.trim().length === 0) {
    throw new Error("A target URL or local project directory is required.");
  }

  if (looksLikeUrl(rawTarget)) {
    return validateUrlTarget(rawTarget, options.confirmAuthorization);
  }

  return validateDirectoryTarget(rawTarget);
}

export function validateUrlTarget(rawTarget: string, confirmAuthorization: boolean): UrlTarget {
  const url = new URL(rawTarget);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only http:// and https:// URL targets are supported.");
  }
  if (url.username || url.password) {
    throw new Error("Credentials in target URLs are not allowed.");
  }
  if (!confirmAuthorization) {
    throw new Error("URL scans require --confirm-authorization.");
  }

  return {
    kind: "url",
    raw: rawTarget,
    url,
    scopeOrigins: [url.origin],
    authorizationConfirmed: true
  };
}

export function validateDirectoryTarget(rawTarget: string): DirectoryTarget {
  const resolved = path.resolve(rawTarget);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Target directory does not exist: ${resolved}`);
  }
  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    throw new Error(`Target is not a directory: ${resolved}`);
  }

  return {
    kind: "directory",
    raw: rawTarget,
    path: resolved
  };
}

export function validateApiSpecTarget(rawTarget: string): ApiSpecTarget {
  const resolved = path.resolve(rawTarget);
  if (!fs.existsSync(resolved)) {
    throw new Error(`OpenAPI specification does not exist: ${resolved}`);
  }
  const stat = fs.statSync(resolved);
  if (!stat.isFile()) {
    throw new Error(`OpenAPI specification is not a file: ${resolved}`);
  }

  return {
    kind: "api-spec",
    raw: rawTarget,
    path: resolved
  };
}

export function assertUrlInScope(target: UrlTarget, url: URL): void {
  if (!target.scopeOrigins.includes(url.origin)) {
    throw new Error(`Out-of-scope URL blocked: ${url.toString()}`);
  }
}

function looksLikeUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}
