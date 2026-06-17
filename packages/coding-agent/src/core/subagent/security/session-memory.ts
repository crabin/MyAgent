import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

export const SECURITY_SUBAGENT_MEMORY_FILE_NAME = "security-subagent-memory.json";

export interface SecuritySessionMemoryContext {
	sessionManager: { getSessionDir(): string };
}

export interface SecuritySessionMemoryClearResult {
	path: string;
	deleted: boolean;
}

export function getSecurityMemoryPath(ctx: SecuritySessionMemoryContext): string {
	return join(ctx.sessionManager.getSessionDir(), SECURITY_SUBAGENT_MEMORY_FILE_NAME);
}

export function clearSecuritySessionMemory(ctx: SecuritySessionMemoryContext): SecuritySessionMemoryClearResult {
	const path = getSecurityMemoryPath(ctx);
	const deleted = existsSync(path);
	rmSync(path, { force: true });
	return { path, deleted };
}
