import path from "node:path";
import { ScanResult } from "../scanner-core/types";
import { writeTextFile } from "../utils/fs";
import { renderHtmlReport } from "./html";
import { renderJsonReport } from "./json";
import { renderMarkdownReport } from "./markdown";
import { renderSarifReport } from "./sarif";
import { redactDeep } from "./sanitize";

export async function writeReports(result: ScanResult, outputDir: string): Promise<Record<string, string>> {
  const outputs: Record<string, string> = {
    markdown: path.join(outputDir, "report.md"),
    html: path.join(outputDir, "report.html"),
    json: path.join(outputDir, "report.json"),
    sarif: path.join(outputDir, "report.sarif")
  };

  await Promise.all([
    writeTextFile(outputs.markdown, renderMarkdownReport(result)),
    writeTextFile(outputs.html, renderHtmlReport(result)),
    writeTextFile(outputs.json, renderJsonReport(result)),
    writeTextFile(outputs.sarif, renderSarifReport(result))
  ]);

  if (result.metadata.sbom) {
    outputs.sbom = path.join(outputDir, "sbom.cdx.json");
    await writeTextFile(outputs.sbom, JSON.stringify(redactDeep(result.metadata.sbom), null, 2));
  }

  return outputs;
}

export { renderHtmlReport, renderJsonReport, renderMarkdownReport, renderSarifReport };
