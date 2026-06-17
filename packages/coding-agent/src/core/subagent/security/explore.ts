import { queryVulnerabilityDb, type VulnerabilityDbSource } from "./vulnerability-db.ts";
import {
	type ApiClientResult,
	apiClient,
	type CrawlPage,
	deepCrawl,
	pageExtract,
	type SearchResult,
	smartSearch,
} from "./web-research.ts";

export interface SecurityExploreInput {
	query: string;
	targetUrl?: string;
	cveId?: string;
	vulnerabilitySource?: VulnerabilityDbSource;
	maxResults?: number;
	crawlDepth?: number;
	crawlPages?: number;
	includeSearch?: boolean;
	includeCrawl?: boolean;
	includeApi?: boolean;
	signal?: AbortSignal;
}

export interface SecurityExploreObservation {
	step: "vulnerability_lookup" | "web_search" | "page_extract" | "deep_crawl" | "api_metadata";
	status: "ok" | "skipped" | "error";
	summary: string;
	sources: string[];
	details?: unknown;
}

export interface SecurityExploreResult {
	mode: "react_explore";
	query: string;
	targetUrl?: string;
	observations: SecurityExploreObservation[];
	recommendedNextSteps: string[];
	contextPatch: {
		focus: string[];
		evidenceCount: number;
		sourceCount: number;
	};
}

export interface SecurityExploreDeps {
	vulnerabilityLookup: typeof queryVulnerabilityDb;
	search: typeof smartSearch;
	extract: typeof pageExtract;
	crawl: typeof deepCrawl;
	api: typeof apiClient;
}

const defaultDeps: SecurityExploreDeps = {
	vulnerabilityLookup: queryVulnerabilityDb,
	search: smartSearch,
	extract: pageExtract,
	crawl: deepCrawl,
	api: apiClient,
};

export async function runSecurityExploration(
	input: SecurityExploreInput,
	deps: SecurityExploreDeps = defaultDeps,
): Promise<SecurityExploreResult> {
	const query = input.query.trim();
	if (!query) throw new Error("query is required");

	const observations: SecurityExploreObservation[] = [];
	const targetUrl = normalizeTargetUrl(input.targetUrl);
	const maxResults = clampInt(input.maxResults ?? 5, 1, 10);
	const includeSearch = input.includeSearch ?? true;
	const includeCrawl = input.includeCrawl ?? false;
	const includeApi = input.includeApi ?? Boolean(targetUrl);

	if (input.cveId || query) {
		observations.push(
			await observe("vulnerability_lookup", async () => {
				const result = await deps.vulnerabilityLookup({
					cveId: input.cveId,
					query,
					source: input.vulnerabilitySource ?? "all",
					limit: maxResults,
					signal: input.signal,
				});
				const count = result.mode === "by_cve_id" ? (result.vuln ? 1 : 0) : result.matchedCount;
				return {
					summary: `Vulnerability lookup completed with ${count} match${count === 1 ? "" : "es"}.`,
					sources: collectVulnerabilitySources(result),
					details: result,
				};
			}),
		);
	}

	if (includeSearch) {
		observations.push(
			await observe("web_search", async () => {
				const result = await deps.search({
					query,
					maxResults,
					fetchPages: false,
					signal: input.signal,
				});
				return {
					summary: `Read-only search returned ${result.total} result${result.total === 1 ? "" : "s"}.`,
					sources: result.results.map((item: SearchResult) => item.url).filter(Boolean),
					details: result,
				};
			}),
		);
	}

	if (targetUrl) {
		observations.push(
			await observe("page_extract", async () => {
				const result = await deps.extract({
					url: targetUrl,
					mode: "structured",
					signal: input.signal,
				});
				return {
					summary: `Extracted structured page metadata for ${result.title || result.url}.`,
					sources: [result.url],
					details: result,
				};
			}),
		);
	} else {
		observations.push({
			step: "page_extract",
			status: "skipped",
			summary: "Skipped page extraction because no target_url was provided.",
			sources: [],
		});
	}

	if (targetUrl && includeCrawl) {
		observations.push(
			await observe("deep_crawl", async () => {
				const result = await deps.crawl({
					startUrl: targetUrl,
					maxDepth: input.crawlDepth,
					maxPages: input.crawlPages,
					sameDomain: true,
					signal: input.signal,
				});
				return {
					summary: `Crawled ${result.pagesCrawled} page${result.pagesCrawled === 1 ? "" : "s"} under the target domain.`,
					sources: result.pages.map((page: CrawlPage) => page.url).filter(Boolean),
					details: result,
				};
			}),
		);
	}

	if (targetUrl && includeApi) {
		observations.push(
			await observe("api_metadata", async () => {
				const host = new URL(targetUrl).hostname;
				const result = await deps.api({
					preset: "dns_resolve",
					query: host,
					timeoutSec: 10,
					signal: input.signal,
				});
				return {
					summary: `Resolved DNS metadata for ${host}.`,
					sources: isApiClientResult(result) ? [result.url] : [],
					details: result,
				};
			}),
		);
	}

	const sources = unique(observations.flatMap((item) => item.sources));
	return {
		mode: "react_explore",
		query,
		targetUrl,
		observations,
		recommendedNextSteps: buildRecommendedNextSteps(targetUrl, observations),
		contextPatch: {
			focus: buildFocus(query, targetUrl, input.cveId),
			evidenceCount: observations.filter((item) => item.status === "ok").length,
			sourceCount: sources.length,
		},
	};
}

async function observe(
	step: SecurityExploreObservation["step"],
	run: () => Promise<{ summary: string; sources: string[]; details?: unknown }>,
): Promise<SecurityExploreObservation> {
	try {
		const result = await run();
		return {
			step,
			status: "ok",
			summary: result.summary,
			sources: unique(result.sources),
			details: result.details,
		};
	} catch (error) {
		return {
			step,
			status: "error",
			summary: error instanceof Error ? error.message : String(error),
			sources: [],
		};
	}
}

function collectVulnerabilitySources(result: Awaited<ReturnType<typeof queryVulnerabilityDb>>): string[] {
	const vulns = result.mode === "by_cve_id" ? (result.vuln ? [result.vuln] : []) : result.matchedVulns;
	return vulns.flatMap((vuln) => vuln.references).filter(Boolean);
}

function buildRecommendedNextSteps(
	targetUrl: string | undefined,
	observations: SecurityExploreObservation[],
): string[] {
	const steps = [
		"Review observations and separate confirmed facts from unverified web evidence.",
		"Verify explicit authorization before any active checks or terminal-based collection.",
	];
	if (targetUrl) {
		steps.push("If in scope, use security_header_check or a narrow security_port_check for bounded validation.");
	}
	if (observations.some((item) => item.step === "vulnerability_lookup" && item.status === "ok")) {
		steps.push("Map relevant CVEs or ATT&CK techniques to affected assets and remediation guidance.");
	}
	steps.push("Use security_report when evidence collection is complete.");
	return steps;
}

function buildFocus(query: string, targetUrl: string | undefined, cveId: string | undefined): string[] {
	const focus = new Set<string>();
	if (targetUrl) focus.add(new URL(targetUrl).hostname);
	if (cveId?.trim()) focus.add(cveId.trim().toUpperCase());
	for (const word of query.split(/\s+/)) {
		const normalized = word.trim().replace(/[^\w.:-]/g, "");
		if (normalized.length >= 4) focus.add(normalized);
		if (focus.size >= 8) break;
	}
	return [...focus];
}

function normalizeTargetUrl(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	if (!trimmed) return undefined;
	const parsed = new URL(trimmed);
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new Error(`target_url must be http or https: ${trimmed}`);
	}
	return parsed.toString();
}

function isApiClientResult(
	value: ApiClientResult | { presets: Array<{ preset: string; description: string }> },
): value is ApiClientResult {
	return "url" in value;
}

function unique(values: string[]): string[] {
	return [...new Set(values.filter(Boolean))];
}

function clampInt(value: number, min: number, max: number): number {
	const integer = Math.trunc(Number.isFinite(value) ? value : min);
	return Math.max(min, Math.min(max, integer));
}
