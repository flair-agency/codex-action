import { constants, openSync, writeSync } from "fs";
import path from "path";
import { performance } from "perf_hooks";
import { randomUUID } from "crypto";

export type LifecyclePhase =
  | "run_started"
  | "pre_spawn_ready"
  | "spawn_requested"
  | "spawned"
  | "spawn_error"
  | "child_error"
  | "deadline_armed"
  | "deadline_fired"
  | "term_attempted"
  | "kill_attempted"
  | "child_exit"
  | "drain_finished"
  | "action_returned";

const ALLOWED_SIGNALS = new Set([
  "SIGABRT",
  "SIGALRM",
  "SIGBUS",
  "SIGCHLD",
  "SIGCONT",
  "SIGFPE",
  "SIGHUP",
  "SIGILL",
  "SIGINT",
  "SIGIO",
  "SIGKILL",
  "SIGPIPE",
  "SIGPROF",
  "SIGQUIT",
  "SIGSEGV",
  "SIGSTOP",
  "SIGSYS",
  "SIGTERM",
  "SIGTRAP",
  "SIGTSTP",
  "SIGTTIN",
  "SIGTTOU",
  "SIGURG",
  "SIGUSR1",
  "SIGUSR2",
  "SIGVTALRM",
  "SIGXCPU",
  "SIGXFSZ",
]);

/** Writes only fixed lifecycle labels and numeric process outcomes to RUNNER_TEMP. */
export class LifecycleTrace {
  private readonly startedAt = performance.now();
  private readonly descriptor: number | null;

  constructor() {
    const runnerTemp = process.env.RUNNER_TEMP;
    if (runnerTemp == null) {
      this.descriptor = null;
      return;
    }

    const filePath = path.join(
      runnerTemp,
      `codex-action-lifecycle-${process.pid}-${randomUUID()}.jsonl`
    );
    try {
      this.descriptor = openSync(
        filePath,
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          (constants.O_NOFOLLOW ?? 0),
        0o600
      );
    } catch {
      this.descriptor = null;
    }
  }

  record(
    phase: LifecyclePhase,
    outcome?: { exitCode: number | null; signal: NodeJS.Signals | null }
  ): void {
    const record: {
      phase: LifecyclePhase;
      elapsedMs: number;
      exitCode?: number | null;
      signal?: string | null;
    } = {
      phase,
      elapsedMs: Math.max(0, Math.round(performance.now() - this.startedAt)),
    };
    if (outcome != null) {
      record.exitCode = outcome.exitCode;
      record.signal =
        outcome.signal == null
          ? null
          : ALLOWED_SIGNALS.has(outcome.signal)
            ? outcome.signal
            : "other";
    }

    const line = `${JSON.stringify(record)}\n`;
    try {
      if (this.descriptor != null) {
        writeSync(this.descriptor, line, undefined, "utf8");
      }
    } catch {
      // Lifecycle diagnostics must never change the action result.
    }

    try {
      process.stderr.write(line, () => {
        // A closed or unavailable workflow log is diagnostic-only.
      });
    } catch {
      // Lifecycle diagnostics must never change the action result.
    }
  }
}
