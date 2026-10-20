export {
  REFUND_DECISION_SCHEMA,
  REFUND_ALARM_SCHEMA,
  asRecord,
  parseLog,
  JsonlEvidenceLog,
  type RefundDecisionRecord,
  type RefundAlarmRecord,
  type RefundOutcome,
  type EvidenceRecord,
  type ParsedLog,
} from "./records.js";
export {
  buildEvidenceReport,
  escapeHtml,
  csvCell,
  formatMoney,
  OUTCOME_LABEL,
  RULE_LABEL,
  type EvidenceReport,
  type EvidenceReportInput,
  type EvidenceSummary,
  type MoneyTotal,
} from "./report.js";
export { runDemo, type DemoOptions, type DemoResult } from "./demo.js";
