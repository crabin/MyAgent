export const SECURITY_SUBAGENT_USER_AGENT =
	"MyAgent-security-subagent/0.1 (+https://github.com/earendil-works/pi; defensive-research)";

interface RobotsRules {
	disallow: string[];
	allow: string[];
	crawlDelaySec: number | null;
}

export interface RobotsDecision {
	allowed: boolean;
	reason: string;
	crawlDelaySec: number;
}

const ROBOTS_CACHE_TTL_MS = 60 * 60 * 1000;
const DEFAULT_MIN_INTERVAL_MS = 1500;
const MAX_MIN_INTERVAL_MS = 8000;

const robotsCache = new Map<string, { rules: RobotsRules | null; fetchedAt: number }>();
const robotsInflight = new Map<string, Promise<RobotsRules | null>>();
const lastRequestAt = new Map<string, number>();

export async function isAllowedByRobots(url: string, signal?: AbortSignal): Promise<RobotsDecision> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return { allowed: false, reason: "URL could not be parsed", crawlDelaySec: 0 };
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return { allowed: false, reason: "Only http/https URLs are allowed", crawlDelaySec: 0 };
	}

	const rules = await getRobotsRules(parsed.origin, signal);
	if (!rules) {
		return { allowed: true, reason: "robots.txt unavailable; default allow with rate limit", crawlDelaySec: 0 };
	}

	const path = parsed.pathname + parsed.search;
	const blockedBy = matchRule(rules.disallow, path);
	if (blockedBy !== null) {
		const allowedBy = matchRule(rules.allow, path);
		if (allowedBy !== null && allowedBy.length >= blockedBy.length) {
			return { allowed: true, reason: `Allow matched: ${allowedBy}`, crawlDelaySec: rules.crawlDelaySec ?? 0 };
		}
		return { allowed: false, reason: `Disallow matched: ${blockedBy}`, crawlDelaySec: rules.crawlDelaySec ?? 0 };
	}
	return { allowed: true, reason: "No Disallow rule matched", crawlDelaySec: rules.crawlDelaySec ?? 0 };
}

export async function rateLimitWait(url: string, crawlDelaySec: number): Promise<number> {
	let host = "";
	try {
		host = new URL(url).host;
	} catch {
		return 0;
	}
	const minInterval = clamp(
		Math.max(DEFAULT_MIN_INTERVAL_MS, Math.ceil(crawlDelaySec * 1000)),
		DEFAULT_MIN_INTERVAL_MS,
		MAX_MIN_INTERVAL_MS,
	);
	const last = lastRequestAt.get(host) ?? 0;
	const now = Date.now();
	const elapsed = now - last;
	if (elapsed >= minInterval) {
		lastRequestAt.set(host, now);
		return 0;
	}
	const waitMs = minInterval - elapsed;
	await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
	lastRequestAt.set(host, Date.now());
	return waitMs;
}

async function getRobotsRules(origin: string, signal?: AbortSignal): Promise<RobotsRules | null> {
	const cached = robotsCache.get(origin);
	if (cached && Date.now() - cached.fetchedAt < ROBOTS_CACHE_TTL_MS) return cached.rules;
	const inflight = robotsInflight.get(origin);
	if (inflight) return inflight;
	const promise = fetchRobots(origin, signal)
		.then((rules) => {
			robotsCache.set(origin, { rules, fetchedAt: Date.now() });
			return rules;
		})
		.catch(() => {
			robotsCache.set(origin, { rules: null, fetchedAt: Date.now() });
			return null;
		})
		.finally(() => {
			robotsInflight.delete(origin);
		});
	robotsInflight.set(origin, promise);
	return promise;
}

async function fetchRobots(origin: string, signal?: AbortSignal): Promise<RobotsRules | null> {
	const controller = new AbortController();
	const abort = () => controller.abort();
	signal?.addEventListener("abort", abort, { once: true });
	const timer = setTimeout(() => controller.abort(), 8000);
	try {
		const res = await fetch(`${origin}/robots.txt`, {
			headers: { "User-Agent": SECURITY_SUBAGENT_USER_AGENT },
			redirect: "follow",
			signal: controller.signal,
		});
		if (!res.ok) return null;
		return parseRobotsTxt(await res.text());
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", abort);
	}
}

function parseRobotsTxt(text: string): RobotsRules {
	const rulesByAgent = new Map<string, { disallow: string[]; allow: string[]; crawlDelay: number | null }>();
	let currentAgents: string[] = [];
	for (const raw of text.split(/\r?\n/)) {
		const line = raw.replace(/#.*$/, "").trim();
		if (!line) continue;
		const colon = line.indexOf(":");
		if (colon === -1) continue;
		const key = line.slice(0, colon).trim().toLowerCase();
		const value = line.slice(colon + 1).trim();
		if (key === "user-agent") {
			currentAgents = value
				.split(/\s+/)
				.filter(Boolean)
				.map((item) => item.toLowerCase());
			for (const ua of currentAgents) {
				if (!rulesByAgent.has(ua)) rulesByAgent.set(ua, { disallow: [], allow: [], crawlDelay: null });
			}
			continue;
		}
		if (!currentAgents.length) continue;
		for (const ua of currentAgents) {
			const ruleset = rulesByAgent.get(ua);
			if (!ruleset) continue;
			if (key === "disallow" && value) ruleset.disallow.push(value);
			else if (key === "allow" && value) ruleset.allow.push(value);
			else if (key === "crawl-delay") {
				const n = Number(value);
				if (Number.isFinite(n) && n >= 0) ruleset.crawlDelay = n;
			}
		}
	}
	const lower = SECURITY_SUBAGENT_USER_AGENT.toLowerCase();
	let chosen = rulesByAgent.get("myagent-security-subagent");
	if (!chosen) {
		for (const [ua, ruleset] of rulesByAgent) {
			if (ua !== "*" && lower.includes(ua)) {
				chosen = ruleset;
				break;
			}
		}
	}
	chosen ??= rulesByAgent.get("*") ?? { disallow: [], allow: [], crawlDelay: null };
	return { disallow: chosen.disallow, allow: chosen.allow, crawlDelaySec: chosen.crawlDelay };
}

function matchRule(patterns: string[], path: string): string | null {
	for (const raw of patterns) {
		const pattern = raw.trim();
		if (!pattern) continue;
		if (pattern === "/") return pattern;
		const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, ".*");
		const re = new RegExp(`^${escaped}`);
		if (re.test(path)) return pattern;
	}
	return null;
}

function clamp(v: number, min: number, max: number): number {
	if (Number.isNaN(v)) return min;
	return Math.min(max, Math.max(min, v));
}
