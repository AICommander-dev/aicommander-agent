import { describe, expect, it } from "vitest";
import {
  MCP_TOOL_METADATA,
  MCP_TOOL_NAMES,
  mcpSecuritySchemes,
  mcpToolMetadata,
} from "../mcp-tool-metadata.js";

const READ_ONLY = [true, false, false, true] as const;
const EXPECTED = {
  remote_exec: [false, true, true, false],
  session_status: READ_ONLY,
  list_machines: READ_ONLY,
  remote_screenshot: READ_ONLY,
  remote_job_start: [false, true, true, false],
  remote_job_list: READ_ONLY,
  remote_job_status: READ_ONLY,
  remote_job_logs: READ_ONLY,
  remote_job_cancel: [false, true, false, true],
  remote_pull: [false, false, false, false],
  remote_push: [false, true, false, false],
} as const;

describe("shared MCP tool metadata", () => {
  it("defines one titled complete classification for each public tool", () => {
    expect(Object.keys(MCP_TOOL_METADATA)).toEqual(MCP_TOOL_NAMES);
    expect(new Set(Object.values(MCP_TOOL_METADATA).map(({ title }) => title)).size).toBe(
      MCP_TOOL_NAMES.length,
    );

    for (const name of MCP_TOOL_NAMES) {
      const metadata = MCP_TOOL_METADATA[name];
      expect(metadata.title).not.toBe("");
      expect(metadata.annotations).toEqual({
        title: metadata.title,
        readOnlyHint: EXPECTED[name][0],
        destructiveHint: EXPECTED[name][1],
        openWorldHint: EXPECTED[name][2],
        idempotentHint: EXPECTED[name][3],
      });
    }
  });

  it("builds oauth2 and noauth descriptors without changing display metadata", () => {
    expect(mcpSecuritySchemes("oauth2")).toEqual([{ type: "oauth2", scopes: ["mcp"] }]);
    expect(mcpSecuritySchemes("noauth")).toEqual([{ type: "noauth" }]);

    for (const name of MCP_TOOL_NAMES) {
      const oauth = mcpToolMetadata(name, "oauth2");
      const noauth = mcpToolMetadata(name, "noauth");
      expect({ title: oauth.title, annotations: oauth.annotations }).toEqual(
        MCP_TOOL_METADATA[name],
      );
      expect({ title: noauth.title, annotations: noauth.annotations }).toEqual(
        MCP_TOOL_METADATA[name],
      );
      expect(oauth._meta.securitySchemes).toEqual(oauth.securitySchemes);
      expect(noauth._meta.securitySchemes).toEqual(noauth.securitySchemes);
    }
  });
});
