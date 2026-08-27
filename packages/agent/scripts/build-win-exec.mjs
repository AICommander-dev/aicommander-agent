#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  throw new Error("The Windows exec launcher must be built on Windows with MSVC");
}

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");
const project = resolve(packageRoot, "native/win-exec-launcher/win-exec-launcher.vcxproj");
const probeProject = resolve(packageRoot, "native/win-exec-launcher/console-probe.vcxproj");
const output = resolve(packageRoot, "dist-native/aicommander-win-exec-x64.exe");
mkdirSync(dirname(output), { recursive: true });

let msbuild = "msbuild.exe";
const programFilesX86 = process.env["ProgramFiles(x86)"];
if (programFilesX86) {
  const vswhere = join(programFilesX86, "Microsoft Visual Studio", "Installer", "vswhere.exe");
  if (existsSync(vswhere)) {
    const found = execFileSync(vswhere, [
      "-latest", "-products", "*", "-requires", "Microsoft.Component.MSBuild",
      "-find", "MSBuild\\**\\Bin\\MSBuild.exe",
    ], { encoding: "utf8" }).trim().split(/\r?\n/)[0];
    if (found) msbuild = found;
  }
}

execFileSync(
  msbuild,
  [project, "/nologo", "/m", "/p:Configuration=Release", "/p:Platform=x64"],
  { stdio: "inherit" },
);
if (process.env["AIC_BUILD_WIN_EXEC_TEST_PROBE"] === "1") {
  execFileSync(
    msbuild,
    [probeProject, "/nologo", "/m", "/p:Configuration=Release", "/p:Platform=x64"],
    { stdio: "inherit" },
  );
}
execFileSync(process.execPath, [resolve(here, "verify-win-exec.mjs"), output], {
  stdio: "inherit",
});
