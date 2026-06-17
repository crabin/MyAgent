import { checkTcpPorts } from "./active-scanning.ts";

export interface NetworkDiscoveryInput {
	targets: string[];
	ports?: number[];
	portProfile?: "common" | "web" | "full";
	portRange?: { start: number; end: number };
	timeoutMs?: number;
	maxHosts?: number;
	signal?: AbortSignal;
}

export interface DiscoveredService {
	port: number;
	service: string;
	status: "open";
}

export interface DiscoveredHost {
	host: string;
	openServices: DiscoveredService[];
	openCount: number;
}

export interface NetworkDiscoveryResult {
	requestedTargets: string[];
	expandedHosts: string[];
	ports: number[];
	hostsScanned: number;
	liveHosts: DiscoveredHost[];
	limits: {
		maxHosts: number;
		timeoutMs: number;
	};
}

const MAX_DISCOVERY_HOSTS = 64;
const COMMON_DISCOVERY_PORTS = [
	1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389,
	427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
	1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
	5000, 5001, 5060, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
	9000, 9090, 9200, 9300, 10000, 11211, 27017, 32768, 49152, 49153, 49154, 49155,
];
const WEB_DISCOVERY_PORTS = [80, 81, 443, 591, 593, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443];

const SERVICE_NAMES: Record<number, string> = {
	21: "ftp",
	22: "ssh",
	23: "telnet",
	25: "smtp",
	53: "dns",
	80: "http",
	110: "pop3",
	143: "imap",
	443: "https",
	445: "smb",
	3306: "mysql",
	3389: "rdp",
	5432: "postgresql",
	8080: "http-alt",
	8443: "https-alt",
};

export async function discoverNetwork(input: NetworkDiscoveryInput): Promise<NetworkDiscoveryResult> {
	const maxHosts = clampInt(input.maxHosts ?? 16, 1, MAX_DISCOVERY_HOSTS);
	const timeoutMs = clampInt(input.timeoutMs ?? 600, 200, 3000);
	const expandedHosts = expandDiscoveryTargets(input.targets, maxHosts);
	const ports = normalizeDiscoveryPorts(input.ports, input.portProfile, input.portRange);
	const liveHosts: DiscoveredHost[] = [];

	for (const host of expandedHosts) {
		if (input.signal?.aborted) break;
		const result = await checkTcpPorts({ host, ports, timeoutMs, signal: input.signal });
		const openServices = result.ports
			.filter((port) => port.open)
			.map((port) => ({
				port: port.port,
				service: SERVICE_NAMES[port.port] ?? "unknown",
				status: "open" as const,
			}));
		if (openServices.length > 0) {
			liveHosts.push({ host, openServices, openCount: openServices.length });
		}
	}

	return {
		requestedTargets: input.targets,
		expandedHosts,
		ports,
		hostsScanned: expandedHosts.length,
		liveHosts,
		limits: { maxHosts, timeoutMs },
	};
}

export function expandDiscoveryTargets(targets: string[], maxHosts = MAX_DISCOVERY_HOSTS): string[] {
	const hosts: string[] = [];
	for (const target of targets) {
		for (const host of expandDiscoveryTarget(target)) {
			if (!hosts.includes(host)) {
				hosts.push(host);
			}
			if (hosts.length >= maxHosts) return hosts;
		}
	}
	return hosts;
}

function expandDiscoveryTarget(target: string): string[] {
	const normalized = normalizeDiscoveryTarget(target);
	if (!normalized) return [];
	if (normalized.includes("/")) {
		return expandIpv4Cidr(normalized);
	}
	return [normalized];
}

function normalizeDiscoveryTarget(target: string): string {
	const trimmed = target.trim().toLowerCase();
	if (!trimmed) return "";
	try {
		const parsed = new URL(trimmed);
		return parsed.hostname;
	} catch {
		return trimmed.replace(/\/+$/, "");
	}
}

function expandIpv4Cidr(cidr: string): string[] {
	const [address, prefixText] = cidr.split("/");
	const prefix = Number(prefixText);
	if (!isIpv4(address) || !Number.isInteger(prefix) || prefix < 24 || prefix > 32) {
		throw new Error("CIDR discovery is limited to IPv4 /24 through /32 ranges.");
	}
	const base = ipv4ToNumber(address);
	const hostCount = 2 ** (32 - prefix);
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	const network = base & mask;
	const hosts: string[] = [];
	for (let offset = 0; offset < hostCount; offset++) {
		const ip = numberToIpv4((network + offset) >>> 0);
		if (prefix < 31 && (offset === 0 || offset === hostCount - 1)) continue;
		hosts.push(ip);
	}
	return hosts;
}

function normalizeDiscoveryPorts(
	ports: number[] | undefined,
	portProfile: NetworkDiscoveryInput["portProfile"],
	portRange: NetworkDiscoveryInput["portRange"],
): number[] {
	const profilePorts = getProfilePorts(portProfile);
	const rangePorts = portRange ? expandPortRange(portRange) : [];
	const normalized = [...(ports ?? []), ...profilePorts, ...rangePorts]
		.map((port) => Math.trunc(port))
		.filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
	const unique = [...new Set(normalized)];
	if (unique.length === 0) {
		throw new Error("At least one TCP port, port profile, or port range is required.");
	}
	return unique;
}

function getProfilePorts(portProfile: NetworkDiscoveryInput["portProfile"]): number[] {
	if (portProfile === "full") {
		return Array.from({ length: 65535 }, (_, index) => index + 1);
	}
	if (portProfile === "web") {
		return WEB_DISCOVERY_PORTS;
	}
	if (portProfile === "common") {
		return COMMON_DISCOVERY_PORTS;
	}
	return [];
}

function expandPortRange(portRange: { start: number; end: number }): number[] {
	const start = clampInt(portRange.start, 1, 65535);
	const end = clampInt(portRange.end, 1, 65535);
	const lower = Math.min(start, end);
	const upper = Math.max(start, end);
	return Array.from({ length: upper - lower + 1 }, (_, index) => lower + index);
}

function isIpv4(value: string): boolean {
	const parts = value.split(".");
	return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function ipv4ToNumber(value: string): number {
	return value.split(".").reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
}

function numberToIpv4(value: number): string {
	return [24, 16, 8, 0].map((shift) => String((value >>> shift) & 255)).join(".");
}

function clampInt(value: number, min: number, max: number): number {
	const integer = Math.trunc(Number.isFinite(value) ? value : min);
	return Math.max(min, Math.min(max, integer));
}
