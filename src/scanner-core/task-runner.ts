import { adapterFailureFinding } from "./finding";
import { ScannerAdapter, ScanContext } from "./types";

export async function runAdapterSafely(adapter: ScannerAdapter, context: ScanContext) {
  try {
    context.logger.info(`Running ${adapter.name}`);
    return await adapter.scan(context);
  } catch (error) {
    context.logger.warn(`${adapter.name} failed safely: ${error instanceof Error ? error.message : String(error)}`);
    return {
      findings: [
        adapterFailureFinding(adapter.name, context.target.raw, error)
      ]
    };
  }
}
