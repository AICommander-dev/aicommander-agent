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
