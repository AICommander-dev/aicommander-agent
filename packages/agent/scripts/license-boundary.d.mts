// Types for license-boundary.mjs, which stays plain ESM: it is executed by
// scripts/release.mjs, scripts/publish-npm.mjs and the mirror's publish
// workflow, none of which have a TypeScript build in front of them.
export declare const LAST_MIT_VERSION: string;
export declare const RELICENSE_VERSION: string;
export declare const MIT: "MIT";
export declare const ELASTIC: "Elastic-2.0";
export declare const BOUNDARY_SENTENCE: string;
export declare function compareVersions(a: string, b: string): -1 | 0 | 1;
export declare function expectedLicenseFor(version: string): "MIT" | "Elastic-2.0";
export declare function publishBlocker(pair: { version: string; license: string }): string | null;
export declare function assertPublishable(pair: { version: string; license: string }): void;
