export const MCP_TOOL_NAMES = [
  "remote_exec",
  "session_status",
  "list_machines",
  "remote_screenshot",
  "remote_job_start",
  "remote_job_list",
  "remote_job_status",
  "remote_job_logs",
  "remote_job_cancel",
  "remote_pull",
  "remote_push",
] as const;

export type McpToolName = (typeof MCP_TOOL_NAMES)[number];

export interface McpToolAnnotations {
  title: string;
  readOnlyHint: boolean;
  destructiveHint: boolean;
  openWorldHint: boolean;
  idempotentHint: boolean;
}

export interface McpToolDisplayMetadata {
  title: string;
  annotations: McpToolAnnotations;
}

const toolMetadata = (
  title: string,
  annotations: Omit<McpToolAnnotations, "title">,
): McpToolDisplayMetadata => ({ title, annotations: { title, ...annotations } });

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false,
  idempotentHint: true,
} as const;

const OPEN_WORLD_DESTRUCTIVE = {
  readOnlyHint: false,
  destructiveHint: true,
  openWorldHint: true,
  idempotentHint: false,
} as const;

export const MCP_TOOL_METADATA: Readonly<Record<McpToolName, McpToolDisplayMetadata>> = {
  remote_exec: toolMetadata("Execute Remote Command", OPEN_WORLD_DESTRUCTIVE),
  session_status: toolMetadata("Check Machine Status", READ_ONLY),
  list_machines: toolMetadata("List Machines", READ_ONLY),
  remote_screenshot: toolMetadata("Capture Remote Screenshot", READ_ONLY),
  remote_job_start: toolMetadata("Start Remote Job", OPEN_WORLD_DESTRUCTIVE),
  remote_job_list: toolMetadata("List Remote Jobs", READ_ONLY),
  remote_job_status: toolMetadata("Check Remote Job Status", READ_ONLY),
  remote_job_logs: toolMetadata("Read Remote Job Logs", READ_ONLY),
  // Repeating cancellation cannot terminate the same process twice.
  remote_job_cancel: toolMetadata("Cancel Remote Job", {
    readOnlyHint: false,
    destructiveHint: true,
    openWorldHint: false,
    idempotentHint: true,
  }),
  // Pulling creates a new relay blob and meters another transfer on every retry.
  remote_pull: toolMetadata("Pull File from Remote Machine", {
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    idempotentHint: false,
  }),
  // Pushing can replace a file and meters another transfer on every retry.
  remote_push: toolMetadata("Push File to Remote Machine", {
    readOnlyHint: false,
    destructiveHint: true,
    openWorldHint: false,
    idempotentHint: false,
  }),
};

export type McpSecurityMode = "oauth2" | "noauth";
export type McpSecurityScheme =
  | { type: "oauth2"; scopes: readonly ["mcp"] }
  | { type: "noauth" };

export function mcpSecuritySchemes(mode: McpSecurityMode): readonly McpSecurityScheme[] {
  return mode === "oauth2"
    ? ([{ type: "oauth2", scopes: ["mcp"] }] as const)
    : ([{ type: "noauth" }] as const);
}

export function mcpToolDisplayMetadata(name: McpToolName): McpToolDisplayMetadata {
  return MCP_TOOL_METADATA[name];
}

export function mcpToolSecurityMetadata(mode: McpSecurityMode) {
  const securitySchemes = mcpSecuritySchemes(mode);
  return { securitySchemes, _meta: { securitySchemes } } as const;
}

export function mcpToolMetadata(name: McpToolName, mode: McpSecurityMode) {
  return {
    ...mcpToolDisplayMetadata(name),
    ...mcpToolSecurityMetadata(mode),
  };
}
