import { errorFields, type DiagFields } from "./diag-log.js";
import { JobError } from "./job-types.js";

/**
 * What a job start that THREW may say in the diagnostic log.
 *
 * A JobError's `code` is the machine-readable cause (`job_script_removed`) and
 * its `detail` names a file of OURS and what happened to it ("wrapper.cmd is
 * gone") — both authored here, both exactly what an antivirus submission needs.
 * The MESSAGE is never logged: it is written for a human, carries prose and a
 * URL today and could carry something else tomorrow. Anything that is not a
 * JobError degrades to `errorFields`, i.e. an errno and a syscall.
 */
export function startFailureFields(err: unknown): DiagFields {
  const fields = errorFields(err);
  const detail = err instanceof JobError ? err.detail : undefined;
  return detail === undefined ? fields : { ...fields, detail };
}
