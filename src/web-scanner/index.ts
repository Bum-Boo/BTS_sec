import { ScannerAdapter } from "../scanner-core/types";
import { accidentalExposureChecker } from "./exposure-checker";
import { cookieFlagChecker } from "./cookie-checker";
import { corsChecker } from "./cors-checker";
import { headerChecker } from "./header-checker";
import { nucleiAdapter } from "./nuclei-adapter";
import { zapBaselineAdapter } from "./zap-adapter";

export function webScannerAdapters(): ScannerAdapter[] {
  return [
    headerChecker,
    cookieFlagChecker,
    corsChecker,
    accidentalExposureChecker,
    zapBaselineAdapter,
    nucleiAdapter
  ];
}

export { ScopedHttpClient } from "./http-client";
export { assertAllowedNucleiTemplates, isAllowedNucleiTemplate, safeNucleiTemplateAllowlist } from "./nuclei-allowlist";
