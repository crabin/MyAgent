import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

export type SecurityTerminalAction = "open" | "exec" | "start" | "read" | "list" | "close";

export interface ShellProfile {
	kind: "posix" | "cmd" | "powershell";
	label: string;
}

export interface SecurityTerminalResult {
	action: SecurityTerminalAction;
	sessionId?: string;
	message?: string;
	output?: string;
	shellProfile?: ShellProfile;
	sessions?: Array<{
		sessionId: string;
		alive: boolean;
		idleSeconds: number;
		pid: number | null;
		shellProfile: ShellProfile;
	}>;
}

export interface SecurityTerminalManager {
	open(cwd?: string): Promise<SecurityTerminalResult>;
	exec(sessionId: string | undefined, command: string, timeoutSec?: number): Promise<SecurityTerminalResult>;
	start(sessionId: string | undefined, command: string): Promise<SecurityTerminalResult>;
	read(sessionId?: string): SecurityTerminalResult;
	list(): SecurityTerminalResult;
	close(sessionId: string): Promise<SecurityTerminalResult>;
	validateCommand(command: string): string | undefined;
}

const OUTPUT_SENTINEL = "__MYAGENT_SECURITY_TERMINAL_DONE__";
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_OUTPUT_CHARS = 40_000;
const sleep = async (ms: number): Promise<void> => {
	await new Promise((resolve) => setTimeout(resolve, ms));
};

export function createSecurityTerminalManager(): SecurityTerminalManager {
	const sessions = new Map<string, SecurityTerminalSession>();

	const cleanupIdleSessions = () => {
		const now = Date.now();
		for (const [sessionId, session] of sessions.entries()) {
			const isIdle = now - session.lastActive > SESSION_IDLE_TIMEOUT_MS;
			if (!session.alive || isIdle) {
				sessions.delete(sessionId);
				void session.close();
			}
		}
	};

	const resolveSession = (sessionId: string | undefined): SecurityTerminalSession => {
		cleanupIdleSessions();
		const normalized = sessionId?.trim();
		if (normalized) {
			const session = sessions.get(normalized);
			if (!session || !session.alive) {
				throw new Error(`Security terminal session does not exist or is closed: ${normalized}`);
			}
			return session;
		}
		const alive = [...sessions.values()].filter((session) => session.alive);
		if (alive.length !== 1) {
			throw new Error("session_id is required when there is not exactly one active security terminal session.");
		}
		return alive[0];
	};

	return {
		async open(cwd) {
			cleanupIdleSessions();
			const sessionId = randomUUID().slice(0, 8);
			const session = new SecurityTerminalSession(sessionId, cwd);
			const message = await session.start();
			sessions.set(sessionId, session);
			return {
				action: "open",
				sessionId,
				message,
				shellProfile: session.shellProfile,
			};
		},
		async exec(sessionId, command, timeoutSec) {
			const validationError = validateSecurityTerminalCommand(command);
			if (validationError) {
				throw new Error(validationError);
			}
			const session = resolveSession(sessionId);
			const output = await session.execute(command, clampTimeout(timeoutSec));
			return {
				action: "exec",
				sessionId: session.sessionId,
				output,
				shellProfile: session.shellProfile,
			};
		},
		async start(sessionId, command) {
			const validationError = validateSecurityTerminalCommand(command);
			if (validationError) {
				throw new Error(validationError);
			}
			const session = resolveSession(sessionId);
			await session.startCommand(command);
			return {
				action: "start",
				sessionId: session.sessionId,
				message: "Security terminal command started asynchronously. Use action=read to poll output.",
				shellProfile: session.shellProfile,
			};
		},
		read(sessionId) {
			const session = resolveSession(sessionId);
			return {
				action: "read",
				sessionId: session.sessionId,
				output: session.read() || "(no new output)",
				shellProfile: session.shellProfile,
			};
		},
		list() {
			cleanupIdleSessions();
			return {
				action: "list",
				sessions: [...sessions.values()].map((session) => ({
					sessionId: session.sessionId,
					alive: session.alive,
					idleSeconds: Math.round((Date.now() - session.lastActive) / 100) / 10,
					pid: session.pid,
					shellProfile: session.shellProfile,
				})),
			};
		},
		async close(sessionId) {
			const normalized = sessionId.trim();
			const session = sessions.get(normalized);
			if (!session) {
				throw new Error(`Security terminal session does not exist: ${normalized}`);
			}
			sessions.delete(normalized);
			return {
				action: "close",
				sessionId: normalized,
				message: await session.close(),
			};
		},
		validateCommand: validateSecurityTerminalCommand,
	};
}

class SecurityTerminalSession {
	readonly sessionId: string;
	private process: ChildProcessWithoutNullStreams | null = null;
	private outputBuffer = "";
	private queue: Promise<unknown> = Promise.resolve();
	private readonly cwd?: string;
	shellProfile: ShellProfile = { kind: "posix", label: "unknown" };
	lastActive = Date.now();

	constructor(sessionId: string, cwd?: string) {
		this.sessionId = sessionId;
		this.cwd = cwd;
	}

	get alive(): boolean {
		return this.process !== null && this.process.exitCode === null && !this.process.killed;
	}

	get pid(): number | null {
		return this.process?.pid ?? null;
	}

	async start(): Promise<string> {
		const resolvedCwd = await resolveCwd(this.cwd);
		const shell = getShellSpec();
		this.shellProfile = { kind: shell.kind, label: shell.label };
		this.process = spawn(shell.command, shell.args, {
			cwd: resolvedCwd,
			env: { ...process.env, TERM: "dumb" },
			stdio: "pipe",
			windowsHide: true,
		});
		this.process.stdout.setEncoding("utf8");
		this.process.stderr.setEncoding("utf8");
		this.process.stdout.on("data", (chunk: string) => this.appendOutput(chunk));
		this.process.stderr.on("data", (chunk: string) => this.appendOutput(chunk));
		this.lastActive = Date.now();
		await sleep(250);
		const banner = this.drainBuffer();
		const prefix = `Security terminal session started (shell=${shell.label}, kind=${shell.kind}, pid=${this.pid ?? "n/a"})`;
		return truncateOutput(banner ? `${prefix}\n${banner}` : prefix);
	}

	execute(command: string, timeoutSec: number): Promise<string> {
		const work = async (): Promise<string> => {
			if (!this.process || !this.alive) {
				throw new Error("Security terminal session is not active.");
			}
			this.lastActive = Date.now();
			this.drainBuffer();

			const marker = `${OUTPUT_SENTINEL}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
			const payload =
				process.platform === "win32" ? `${command}\r\necho ${marker}\r\n` : `${command}\necho ${marker}\n`;
			this.process.stdin.write(payload, "utf8");

			const deadline = Date.now() + timeoutSec * 1000;
			while (Date.now() < deadline) {
				if (this.outputBuffer.includes(marker)) break;
				if (!this.alive) break;
				await sleep(80);
			}

			const output = this.drainBuffer();
			if (!output.includes(marker) && Date.now() >= deadline) {
				throw new Error(`Security terminal command timeout after ${timeoutSec}s`);
			}
			return truncateOutput(cleanOutput(output, command, marker));
		};

		const run = this.queue.then(work, work);
		this.queue = run.then(
			() => undefined,
			() => undefined,
		);
		return run;
	}

	startCommand(command: string): Promise<void> {
		const work = async (): Promise<void> => {
			if (!this.process || !this.alive) {
				throw new Error("Security terminal session is not active.");
			}
			this.lastActive = Date.now();
			this.drainBuffer();
			const payload = process.platform === "win32" ? `${command}\r\n` : `${command}\n`;
			this.process.stdin.write(payload, "utf8");
			await sleep(80);
		};
		const run = this.queue.then(work, work);
		this.queue = run.then(
			() => undefined,
			() => undefined,
		);
		return run;
	}

	read(): string {
		this.lastActive = Date.now();
		return truncateOutput(this.drainBuffer());
	}

	async close(): Promise<string> {
		if (!this.process) {
			return `Security terminal session closed (session=${this.sessionId})`;
		}
		if (this.alive) {
			this.process.stdin.write("exit\n", "utf8");
		}
		await this.waitForExit(3000);
		if (this.alive) {
			this.process.kill();
			await this.waitForExit(1000);
		}
		const remaining = this.drainBuffer();
		const prefix = `Security terminal session closed (session=${this.sessionId})`;
		return truncateOutput(remaining ? `${prefix}\n${remaining}` : prefix);
	}

	private waitForExit(timeoutMs: number): Promise<void> {
		if (!this.process || !this.alive) {
			return Promise.resolve();
		}
		return new Promise((resolve) => {
			const proc = this.process;
			if (!proc) {
				resolve();
				return;
			}
			const timer = setTimeout(() => resolve(), timeoutMs);
			proc.once("close", () => {
				clearTimeout(timer);
				resolve();
			});
		});
	}

	private appendOutput(chunk: string): void {
		this.outputBuffer += chunk;
		if (this.outputBuffer.length > 200_000) {
			this.outputBuffer = this.outputBuffer.slice(-100_000);
		}
	}

	private drainBuffer(): string {
		const output = this.outputBuffer;
		this.outputBuffer = "";
		return output;
	}
}

function validateSecurityTerminalCommand(command: string): string | undefined {
	const trimmed = command.trim();
	if (!trimmed) return "command is required.";
	return undefined;
}

function getShellSpec(): { command: string; args: string[]; label: string; kind: ShellProfile["kind"] } {
	if (process.platform === "win32") {
		const comspec = process.env.COMSPEC || "cmd.exe";
		const lower = comspec.toLowerCase();
		const kind: ShellProfile["kind"] =
			lower.includes("powershell") || lower.endsWith("pwsh.exe") ? "powershell" : "cmd";
		return { command: comspec, args: [], label: path.basename(comspec), kind };
	}
	const shell = process.env.SHELL || "/bin/bash";
	return { command: shell, args: [], label: path.basename(shell), kind: "posix" };
}

async function resolveCwd(cwd?: string): Promise<string | undefined> {
	if (!cwd || !cwd.trim()) return undefined;
	const resolved = path.resolve(cwd.trim());
	const stat = await fs.stat(resolved);
	if (!stat.isDirectory()) {
		throw new Error(`Working directory is not a directory: ${resolved}`);
	}
	return resolved;
}

function cleanOutput(output: string, command: string, marker: string): string {
	const lines = output.split(/\r?\n/);
	const cleaned: string[] = [];
	for (const line of lines) {
		const stripped = line.trim();
		if (stripped.includes(marker)) continue;
		if (stripped === `echo ${marker}`) continue;
		cleaned.push(line);
	}
	let text = cleaned.join("\n").trim();
	if (text.startsWith(command.trim())) {
		text = text.slice(command.trim().length).trimStart();
	}
	return text;
}

function clampTimeout(timeoutSec: number | undefined): number {
	if (!timeoutSec || !Number.isFinite(timeoutSec) || timeoutSec <= 0) return 30;
	return Math.min(7200, Math.max(1, Math.trunc(timeoutSec)));
}

function truncateOutput(output: string): string {
	if (output.length <= MAX_OUTPUT_CHARS) return output;
	return `${output.slice(0, MAX_OUTPUT_CHARS)}\n[truncated ${output.length - MAX_OUTPUT_CHARS} chars]`;
}
