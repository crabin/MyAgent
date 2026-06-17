import { Socket } from "node:net";

export interface PortCheckInput {
	host: string;
	ports?: number[];
	portRange?: { start: number; end: number };
	timeoutMs?: number;
	signal?: AbortSignal;
}

export interface PortCheckResult {
	host: string;
	ports: Array<{ port: number; open: boolean; status: "open" | "closed" | "filtered" | "aborted" }>;
	openCount: number;
}

export interface HeaderCheckResult {
	url: string;
	status: number;
	headers: {
		present: string[];
		missing: string[];
	};
	score: number;
}

const SECURITY_HEADERS = [
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-XSS-Protection",
	"Referrer-Policy",
];

export async function checkTcpPorts(input: PortCheckInput): Promise<PortCheckResult> {
	const host = normalizeHost(input.host);
	if (!host) {
		throw new Error("host is required.");
	}
	const ports = normalizePorts(input.ports, input.portRange);
	const timeoutMs = clampNumber(input.timeoutMs ?? 1000, 200, 5000);
	const results: PortCheckResult["ports"] = [];
	const batchSize = ports.length > 1000 ? 200 : 10;

	for (let index = 0; index < ports.length; index += batchSize) {
		if (input.signal?.aborted) break;
		const batch = ports.slice(index, index + batchSize);
		const batchResults = await Promise.all(batch.map((port) => checkTcpPort(host, port, timeoutMs, input.signal)));
		results.push(...batchResults);
	}

	return {
		host,
		ports: results,
		openCount: results.filter((result) => result.open).length,
	};
}

export async function checkSecurityHeaders(url: string, signal?: AbortSignal): Promise<HeaderCheckResult> {
	const parsed = normalizeHttpUrl(url);
	const response = await fetch(parsed, { method: "HEAD", signal });
	const present: string[] = [];
	const missing: string[] = [];

	for (const header of SECURITY_HEADERS) {
		if (response.headers.has(header)) {
			present.push(header);
		} else {
			missing.push(header);
		}
	}

	return {
		url: parsed.toString(),
		status: response.status,
		headers: { present, missing },
		score: Math.round((present.length / SECURITY_HEADERS.length) * 100),
	};
}

export function extractHostname(target: string): string {
	return normalizeHost(target);
}

function checkTcpPort(
	host: string,
	port: number,
	timeoutMs: number,
	signal: AbortSignal | undefined,
): Promise<PortCheckResult["ports"][number]> {
	return new Promise((resolve) => {
		const socket = new Socket();
		let settled = false;

		const finish = (open: boolean, status: PortCheckResult["ports"][number]["status"]) => {
			if (settled) return;
			settled = true;
			socket.destroy();
			resolve({ port, open, status });
		};

		socket.setTimeout(timeoutMs);
		socket.on("connect", () => finish(true, "open"));
		socket.on("timeout", () => finish(false, "filtered"));
		socket.on("error", () => finish(false, "closed"));

		if (signal?.aborted) {
			finish(false, "aborted");
			return;
		}
		const abort = () => finish(false, "aborted");
		signal?.addEventListener("abort", abort, { once: true });
		socket.on("close", () => signal?.removeEventListener("abort", abort));
		socket.connect(port, host);
	});
}

function normalizePorts(ports: number[] | undefined, portRange: PortCheckInput["portRange"]): number[] {
	const rangePorts = portRange ? expandPortRange(portRange) : [];
	const normalized = [...(ports ?? []), ...rangePorts]
		.map((port) => Math.trunc(port))
		.filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
	const unique = [...new Set(normalized)];
	if (unique.length === 0) {
		throw new Error("At least one TCP port, port profile, or port range is required.");
	}
	return unique;
}

function expandPortRange(portRange: { start: number; end: number }): number[] {
	const start = clampNumber(portRange.start, 1, 65535);
	const end = clampNumber(portRange.end, 1, 65535);
	const lower = Math.min(start, end);
	const upper = Math.max(start, end);
	return Array.from({ length: upper - lower + 1 }, (_, index) => lower + index);
}

function normalizeHost(target: string): string {
	const trimmed = target.trim().toLowerCase();
	if (!trimmed) return "";
	try {
		const parsed = new URL(trimmed);
		return parsed.hostname;
	} catch {
		return trimmed.replace(/\/+$/, "");
	}
}

function normalizeHttpUrl(url: string): URL {
	const parsed = new URL(url);
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new Error("Only HTTP and HTTPS URLs are supported.");
	}
	return parsed;
}

function clampNumber(value: number, min: number, max: number): number {
	if (!Number.isFinite(value)) return min;
	return Math.min(max, Math.max(min, Math.trunc(value)));
}
