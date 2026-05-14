import { ScannerAdapter } from "../scanner-core/types";
import { openApiScanner } from "./openapi-scanner";

export function apiScannerAdapters(): ScannerAdapter[] {
  return [openApiScanner];
}

export { openApiScanner };
