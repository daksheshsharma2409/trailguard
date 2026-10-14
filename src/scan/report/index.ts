/**
 * Static analysis reporters (Markdown, JSON).
 *
 * @see context.md §6.12
 */

export {
  formatMarkdownReport,
  REPORT_CAVEAT,
  REPORT_LIMITATIONS,
} from './markdown.js';
export type { MarkdownReportOptions } from './markdown.js';

export {
  formatJsonReport,
  parseJsonReport,
  validateScanResult,
  ScanResultSchema,
} from './json.js';

export { formatSarifReport } from './sarif.js';
export type {
  SarifLog,
  SarifRun,
  SarifResult,
  SarifReportingDescriptor,
  SarifLocation,
  SarifSuppression,
} from './sarif.js';

