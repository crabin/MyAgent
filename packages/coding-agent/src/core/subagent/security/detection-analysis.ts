export type DetectionSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface DetectionEvent {
	timestamp?: string;
	source: string;
	eventType: string;
	message: string;
	severity?: DetectionSeverity;
	srcIp?: string;
	destIp?: string;
	destPort?: number;
	username?: string;
}

export interface DetectionFinding {
	title: string;
	severity: DetectionSeverity;
	category: "authentication" | "network_reconnaissance" | "web_attack" | "malware_indicator";
	confidence: "low" | "medium" | "high";
	evidence: string[];
	mitreTechnique?: string;
	recommendedActions: string[];
}

export interface DetectionAnalysisInput {
	events: DetectionEvent[];
}

export interface DetectionAnalysisResult {
	summary: {
		totalEvents: number;
		totalFindings: number;
		bySeverity: Record<DetectionSeverity, number>;
	};
	findings: DetectionFinding[];
	limitations: string[];
}

const SEVERITIES: DetectionSeverity[] = ["critical", "high", "medium", "low", "info"];
const FAILED_LOGIN_PATTERN = /\b(failed|failure|invalid|denied)\b.*\b(login|logon|auth|authentication|password)\b/i;
const PORT_SCAN_EVENT_TYPES = new Set(["connection", "flow", "network", "firewall"]);
const WEB_ATTACK_PATTERNS = [
	{ pattern: /(\.\.\/|\.\.\\|%2e%2e%2f|path traversal)/i, title: "Path traversal indicator observed" },
	{ pattern: /(union\s+select|or\s+1\s*=\s*1|sql injection|sqli)/i, title: "SQL injection indicator observed" },
	{ pattern: /(<script|xss|cross-site scripting)/i, title: "Cross-site scripting indicator observed" },
];
const MALWARE_PATTERNS = [
	{
		pattern: /(mimikatz|credential dump|lsass)/i,
		title: "Credential dumping indicator observed",
		severity: "critical",
	},
	{
		pattern: /(webshell|web shell|reverse shell|bind shell)/i,
		title: "Shell activity indicator observed",
		severity: "high",
	},
	{
		pattern: /(encodedcommand|frombase64string|powershell -enc)/i,
		title: "Encoded PowerShell indicator observed",
		severity: "high",
	},
] satisfies Array<{ pattern: RegExp; title: string; severity: DetectionSeverity }>;

export function analyzeDetections(input: DetectionAnalysisInput): DetectionAnalysisResult {
	const events = input.events.slice(0, 500);
	const findings = [
		...detectAuthenticationBursts(events),
		...detectNetworkReconnaissance(events),
		...detectWebAttackIndicators(events),
		...detectMalwareIndicators(events),
	].sort(compareFindings);
	return {
		summary: summarize(events, findings),
		findings,
		limitations: [
			"This analysis only evaluates provided events and does not monitor live traffic.",
			"Detections are heuristic indicators and should be validated against asset context and baseline behavior.",
			"Evidence may be incomplete if logs were truncated, normalized, or collected from only one sensor.",
		],
	};
}

function detectAuthenticationBursts(events: DetectionEvent[]): DetectionFinding[] {
	const groups = new Map<string, DetectionEvent[]>();
	for (const event of events) {
		const text = `${event.eventType} ${event.message}`;
		if (!FAILED_LOGIN_PATTERN.test(text)) {
			continue;
		}
		const actor = event.srcIp ?? event.username ?? event.source;
		const key = `${actor}|${event.username ?? "unknown-user"}`;
		const grouped = groups.get(key) ?? [];
		grouped.push(event);
		groups.set(key, grouped);
	}
	const findings: DetectionFinding[] = [];
	for (const [key, grouped] of groups) {
		if (grouped.length < 5) {
			continue;
		}
		const [actor, username] = key.split("|");
		findings.push({
			title: "Repeated authentication failures",
			severity: grouped.length >= 10 ? "high" : "medium",
			category: "authentication",
			confidence: "medium",
			evidence: grouped.slice(0, 5).map(formatEventEvidence),
			mitreTechnique: "T1110",
			recommendedActions: [
				`Review authentication attempts from ${actor} against ${username}.`,
				"Confirm whether MFA, lockout policy, and source IP allowlists are enforced.",
				"Search adjacent identity logs for successful logins after the failure burst.",
			],
		});
	}
	return findings;
}

function detectNetworkReconnaissance(events: DetectionEvent[]): DetectionFinding[] {
	const bySource = new Map<string, Set<number>>();
	const examples = new Map<string, DetectionEvent[]>();
	for (const event of events) {
		if (!event.srcIp || typeof event.destPort !== "number") {
			continue;
		}
		if (!PORT_SCAN_EVENT_TYPES.has(event.eventType.toLowerCase())) {
			continue;
		}
		const ports = bySource.get(event.srcIp) ?? new Set<number>();
		ports.add(event.destPort);
		bySource.set(event.srcIp, ports);
		const sample = examples.get(event.srcIp) ?? [];
		if (sample.length < 5) {
			sample.push(event);
			examples.set(event.srcIp, sample);
		}
	}
	const findings: DetectionFinding[] = [];
	for (const [srcIp, ports] of bySource) {
		if (ports.size < 5) {
			continue;
		}
		findings.push({
			title: "Possible port scanning behavior",
			severity: ports.size >= 20 ? "high" : "medium",
			category: "network_reconnaissance",
			confidence: "medium",
			evidence: (examples.get(srcIp) ?? []).map(formatEventEvidence),
			mitreTechnique: "T1046",
			recommendedActions: [
				`Validate whether ${srcIp} is an authorized scanner or expected monitoring source.`,
				"Correlate with firewall, endpoint, and vulnerability scanner schedules.",
				"Restrict or alert on unauthorized broad port probing.",
			],
		});
	}
	return findings;
}

function detectWebAttackIndicators(events: DetectionEvent[]): DetectionFinding[] {
	const findings: DetectionFinding[] = [];
	for (const rule of WEB_ATTACK_PATTERNS) {
		const matched = events.filter((event) => rule.pattern.test(event.message)).slice(0, 5);
		if (matched.length === 0) {
			continue;
		}
		findings.push({
			title: rule.title,
			severity: "medium",
			category: "web_attack",
			confidence: "medium",
			evidence: matched.map(formatEventEvidence),
			mitreTechnique: "T1190",
			recommendedActions: [
				"Confirm whether the request reached an in-scope application and whether the application returned errors.",
				"Review WAF, application, and endpoint logs for follow-on activity from the same source.",
				"Patch vulnerable handlers and add input validation or request filtering where appropriate.",
			],
		});
	}
	return findings;
}

function detectMalwareIndicators(events: DetectionEvent[]): DetectionFinding[] {
	const findings: DetectionFinding[] = [];
	for (const rule of MALWARE_PATTERNS) {
		const matched = events.filter((event) => rule.pattern.test(`${event.eventType} ${event.message}`)).slice(0, 5);
		if (matched.length === 0) {
			continue;
		}
		findings.push({
			title: rule.title,
			severity: rule.severity,
			category: "malware_indicator",
			confidence: "medium",
			evidence: matched.map(formatEventEvidence),
			mitreTechnique: rule.severity === "critical" ? "T1003" : "T1059",
			recommendedActions: [
				"Preserve affected host logs and relevant process/network telemetry.",
				"Isolate confirmed affected systems according to the incident response plan.",
				"Run endpoint triage and search for related indicators across the environment.",
			],
		});
	}
	return findings;
}

function summarize(events: DetectionEvent[], findings: DetectionFinding[]): DetectionAnalysisResult["summary"] {
	const bySeverity: Record<DetectionSeverity, number> = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0,
	};
	for (const finding of findings) {
		bySeverity[finding.severity] += 1;
	}
	return {
		totalEvents: events.length,
		totalFindings: findings.length,
		bySeverity,
	};
}

function compareFindings(a: DetectionFinding, b: DetectionFinding): number {
	const severityDelta = SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);
	if (severityDelta !== 0) return severityDelta;
	return a.title.localeCompare(b.title);
}

function formatEventEvidence(event: DetectionEvent): string {
	const parts = [
		event.timestamp,
		event.source,
		event.srcIp ? `src=${event.srcIp}` : "",
		event.destIp ? `dst=${event.destIp}` : "",
		typeof event.destPort === "number" ? `port=${event.destPort}` : "",
		event.username ? `user=${event.username}` : "",
		event.message,
	];
	return parts.filter(Boolean).join(" | ").slice(0, 500);
}
