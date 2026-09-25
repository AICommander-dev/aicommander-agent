// Public surface of @aicommander/priv-helper.
//
// The CLIENT-SAFE contract (imported by the agent's IPC client): the wire
// protocol + framing and the endpoint paths. These pull in no privileged code.
export * from "./protocol.js";
export * from "./endpoint.js";
export * from "./types.js";

// The SERVER side (transport, executor, capability verification, helper wiring)
// is appended by its owning modules and is consumed by bin/priv-helper.ts.
// windows-exec-launcher also owns the shared native-launcher wire codec reused
// by the ordinary agent; the privileged path adds sibling/PE verification.
export * from "./windows-exec-launcher.js";
export * from "./transport.js";
export * from "./executor.js";
export * from "./lease-manager.js";
export * from "./capability-verify.js";
export * from "./boot-challenge.js";
export * from "./pinned-key.js";
export * from "./helper.js";
export * from "./win-watchdog.js";
export * from "./win-watchdog-install.js";
export * from "./win-watchdog-probe.js";
export * from "./version.js";
