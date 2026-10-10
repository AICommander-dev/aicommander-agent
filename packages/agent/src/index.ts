export { register } from "./register.js";
export { runConnectionLoop } from "./connection.js";
export { AgentController } from "./agent-controller.js";
export type { AgentStatus, ScreenShareProvider, RemoteConnectInfo } from "./agent-controller.js";
export { fetchAdmins, blockAdmin, unblockAdmin, orderAdmins, resolveAdminIdentifier } from "./device-admin.js";
export type { AdminEntry, AdminsResult, BlockResult } from "./device-admin.js";
export { captureScreenshot, canCaptureScreenshot, listDisplays } from "./screenshot.js";
export type { CapturedScreenshot, ScreenshotOptions } from "./screenshot.js";
export { runSupervisor } from "./supervisor.js";
export type { SupervisorOptions } from "./supervisor.js";
export {
  startHeartbeat,
  stopHeartbeat,
  readHeartbeat,
  defaultHeartbeatPath,
} from "./heartbeat.js";
export {
  compareVersions,
  isNewerVersion,
  fetchLatestDist,
} from "./update-check.js";
export type { LatestDist } from "./update-check.js";
export { AGENT_VERSION } from "./version.js";
export type { TokenVault, SessionStoreContext } from "./session-store.js";
export { CredentialStorageError, isStrictCredentialStorage } from "./credential-storage.js";
export {
  initDiagLog,
  diag,
  diagJobId,
  diagLogPath,
  exitAfterDiagFlush,
  flushDiagLog,
  closeDiagLog,
  errorFields,
  logStartup,
  redactDiagText,
  redactHomePaths,
  resolveDiagLogDir,
} from "./diag-log.js";
export type { DiagEvent, DiagFields, DiagLogOptions, DiagRole, DiagValue } from "./diag-log.js";
// `doctor` — the check library behind `aicommander-agent doctor`, exported so
// the desktop tray and the Windows privileged helper can run the SAME checks
// without going through the CLI (PLAN-av-hardening §2 W2.2/W2.3).
export {
  runDoctor,
  resolveDoctorContext,
  renderDoctorReport,
  doctorReportBundle,
  doctorReportJson,
  redactDoctorReport,
} from "./doctor/index.js";
export type {
  CheckResult,
  CheckVerdict,
  DoctorContext,
  DoctorFacts,
  DoctorOptions,
  DoctorReport,
  DoctorSummary,
  DoctorTokenVault,
  RenderOptions,
} from "./doctor/index.js";
