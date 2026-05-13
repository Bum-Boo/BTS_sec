import { ScannerAdapter } from "../scanner-core/types";
import { gitleaksAdapter } from "./gitleaks-adapter";
import { internalSecretScanner } from "./internal-secret-scanner";
import { truffleHogAdapter } from "./trufflehog-adapter";

export function secretScannerAdapters(): ScannerAdapter[] {
  return [
    internalSecretScanner,
    gitleaksAdapter,
    truffleHogAdapter
  ];
}

export { redactSecrets } from "./redactor";
