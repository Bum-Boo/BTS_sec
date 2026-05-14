import { ScannerAdapter } from "../scanner-core/types";
import { npmAuditAdapter } from "./npm-audit-adapter";
import { osvScannerAdapter } from "./osv-adapter";
import { pipAuditAdapter } from "./pip-audit-adapter";
import { supplyChainScanner } from "./supply-chain-scanner";
import { trivyAdapter } from "./trivy-adapter";

export function dependencyScannerAdapters(): ScannerAdapter[] {
  return [
    supplyChainScanner,
    trivyAdapter,
    osvScannerAdapter,
    npmAuditAdapter,
    pipAuditAdapter
  ];
}

export { generateSbom } from "./sbom";
