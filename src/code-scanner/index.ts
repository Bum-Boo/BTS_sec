import { ScannerAdapter } from "../scanner-core/types";
import { customCodeScanner } from "./custom-rules";
import { semgrepAdapter } from "./semgrep-adapter";

export function codeScannerAdapters(): ScannerAdapter[] {
  return [
    customCodeScanner,
    semgrepAdapter
  ];
}
