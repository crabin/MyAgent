import {
	applySimpleSelector,
	cleanHtmlToText,
	extractHeadings,
	extractImages,
	extractLinks,
	extractMetaTags,
	extractTitle,
	normalizeUrlForVisit,
} from "./html-utils.ts";
import { isAllowedByRobots, rateLimitWait, SECURITY_SUBAGENT_USER_AGENT } from "./robots.ts";

export interface SearchResult {
	title: string;
	url: string;
	snippet: string;
	pageContent?: string;
}

export interface PageExtractResult {
	url: string;
	title: string;
	mode: "text" | "structured";
	content?: string;
	contentLength?: number;
	links?: Array<{ text: string; url: string }>;
	images?: Array<{ alt: string; src: string }>;
	headings?: Array<{ level: number; text: string }>;
	meta?: Record<string, string>;
	robots: string;
}

export interface CrawlPage {
	url: string;
	depth: number;
	title: string;
	contentPreview: string;
	contentLength: number;
	linksFound: number;
	links: Array<{ text: string; url: string }>;
}

export interface CrawlError {
	url: string;
	depth: number;
	message: string;
}

export interface ApiClientResult {
	url: string;
	method: string;
	statusCode: number;
	ok: boolean;
	contentType: string;
	elapsedMs: number;
	responseHeaders: Record<string, string>;
	data?: unknown;
	bodyPreview?: string;
	truncated?: boolean;
}

const SEARCH_TIMEOUT_MS = 8000;
const PAGE_FETCH_TIMEOUT_MS = 15000;

export async function smartSearch(args: {
	query: string;
	maxResults?: number;
	fetchPages?: boolean;
	signal?: AbortSignal;
}): Promise<{ query: string; total: number; results: SearchResult[] }> {
	const query = args.query.trim();
	if (!query) throw new Error("Missing query");
	const maxResults = clampInt(args.maxResults ?? 3, 1, 10);
	const results = await searchDuckDuckGo(query, maxResults, args.signal);
	const withPages = args.fetchPages === false ? results : await fetchSearchPages(results, args.signal);
	return { query, total: withPages.length, results: withPages };
}

export async function pageExtract(args: {
	url: string;
	mode?: "text" | "structured";
	cssSelector?: string;
	timeoutMs?: number;
	signal?: AbortSignal;
}): Promise<PageExtractResult> {
	const url = normalizeHttpUrl(args.url);
	const robots = await isAllowedByRobots(url, args.signal);
	if (!robots.allowed) throw new Error(`Blocked by robots.txt: ${robots.reason}`);
	await rateLimitWait(url, robots.crawlDelaySec);
	const page = await fetchHtmlPage(url, args.timeoutMs ?? PAGE_FETCH_TIMEOUT_MS, args.signal);
	const focusedHtml = args.cssSelector ? applySimpleSelector(page.html, args.cssSelector) : page.html;
	const mode = args.mode ?? "text";
	if (mode === "structured") {
		return {
			url: page.url,
			title: page.title,
			mode,
			headings: extractHeadings(focusedHtml, 50),
			meta: extractMetaTags(focusedHtml, 20),
			links: extractLinks(focusedHtml, page.url, 40),
			images: extractImages(focusedHtml, page.url, 20),
			robots: robots.reason,
		};
	}
	const content = cleanHtmlToText(focusedHtml);
	return {
		url: page.url,
		title: page.title,
		mode: "text",
		content: content.slice(0, 8000),
		contentLength: content.length,
		links: extractLinks(focusedHtml, page.url, 30),
		images: extractImages(focusedHtml, page.url, 10),
		robots: robots.reason,
	};
}

export async function deepCrawl(args: {
	startUrl: string;
	maxDepth?: number;
	maxPages?: number;
	sameDomain?: boolean;
	urlPattern?: string;
	signal?: AbortSignal;
}): Promise<{
	startUrl: string;
	maxDepth: number;
	pagesCrawled: number;
	pages: CrawlPage[];
	errors: CrawlError[];
	partial: boolean;
}> {
	const startUrl = normalizeHttpUrl(args.startUrl);
	const maxDepth = clampInt(args.maxDepth ?? 1, 0, 3);
	const maxPages = clampInt(args.maxPages ?? 5, 1, 20);
	const sameDomain = args.sameDomain ?? true;
	let pattern: RegExp | undefined;
	if (args.urlPattern?.trim()) {
		pattern = new RegExp(args.urlPattern.trim());
	}

	const start = new URL(startUrl);
	const baseHost = start.hostname.toLowerCase();
	const queue: Array<{ url: string; depth: number }> = [{ url: start.toString(), depth: 0 }];
	const visited = new Set<string>([normalizeUrlForVisit(start.toString())]);
	const pages: CrawlPage[] = [];
	const errors: CrawlError[] = [];

	while (queue.length > 0 && pages.length < maxPages) {
		const item = queue.shift();
		if (!item) break;
		const crawled = await crawlOnePage(item.url, item.depth, args.signal);
		if (!crawled.ok) {
			errors.push({ url: item.url, depth: item.depth, message: crawled.error });
			continue;
		}
		const page = crawled.page;
		pages.push(page);
		if (item.depth >= maxDepth) continue;

		for (const link of page.links) {
			if (pages.length + queue.length >= maxPages * 2) break;
			const normalized = normalizeUrlForVisit(link.url);
			if (visited.has(normalized)) continue;
			let parsed: URL;
			try {
				parsed = new URL(link.url);
			} catch {
				continue;
			}
			if (sameDomain && parsed.hostname.toLowerCase() !== baseHost) continue;
			if (pattern && !pattern.test(link.url)) continue;
			visited.add(normalized);
			queue.push({ url: link.url, depth: item.depth + 1 });
		}
	}

	return {
		startUrl,
		maxDepth,
		pagesCrawled: pages.length,
		pages: pages.slice(0, maxPages),
		errors,
		partial: errors.length > 0,
	};
}

export async function apiClient(args: {
	url?: string;
	preset?: string;
	query?: string;
	method?: string;
	headers?: Record<string, string>;
	params?: Record<string, string>;
	body?: unknown;
	timeoutSec?: number;
	signal?: AbortSignal;
}): Promise<ApiClientResult | { presets: Array<{ preset: string; description: string }> }> {
	const preset = args.preset?.trim();
	if (preset) return executePreset(preset, args);
	if (!args.url?.trim()) {
		return {
			presets: Object.entries(API_PRESETS).map(([key, value]) => ({
				preset: key,
				description: value.description,
			})),
		};
	}
	return executeRequest({
		url: args.url,
		method: args.method ?? "GET",
		headers: args.headers ?? {},
		params: args.params,
		body: args.body,
		timeoutSec: args.timeoutSec,
		signal: args.signal,
	});
}

const API_PRESETS: Record<
	string,
	{ urlTemplate: string; method: string; description: string; headers?: Record<string, string> }
> = {
	dns_resolve: {
		urlTemplate: "https://dns.google/resolve?name={query}&type=A",
		method: "GET",
		description: "Resolve DNS A records through Google DNS over HTTPS.",
	},
	github_repo: {
		urlTemplate: "https://api.github.com/repos/{query}",
		method: "GET",
		description: "Query GitHub repository metadata.",
		headers: { Accept: "application/vnd.github+json" },
	},
	github_user: {
		urlTemplate: "https://api.github.com/users/{query}",
		method: "GET",
		description: "Query GitHub user metadata.",
		headers: { Accept: "application/vnd.github+json" },
	},
	ip_info: {
		urlTemplate: "http://ip-api.com/json/{query}?lang=en",
		method: "GET",
		description: "Geolocation and ASN details for an IP address.",
	},
	ip_self: {
		urlTemplate: "https://httpbin.org/ip",
		method: "GET",
		description: "Return the current public IP observed by httpbin.",
	},
};

async function executePreset(
	preset: string,
	args: {
		query?: string;
		headers?: Record<string, string>;
		timeoutSec?: number;
		signal?: AbortSignal;
	},
): Promise<ApiClientResult> {
	const config = API_PRESETS[preset];
	if (!config) throw new Error(`Unknown preset: ${preset}`);
	if (config.urlTemplate.includes("{query}") && !args.query?.trim()) {
		throw new Error(`Preset ${preset} requires query`);
	}
	const url = config.urlTemplate.replace("{query}", encodeURIComponent(args.query?.trim() ?? ""));
	return executeRequest({
		url,
		method: config.method,
		headers: { ...(config.headers ?? {}), ...(args.headers ?? {}) },
		timeoutSec: args.timeoutSec,
		signal: args.signal,
	});
}

async function executeRequest(args: {
	url: string;
	method: string;
	headers: Record<string, string>;
	params?: Record<string, string>;
	body?: unknown;
	timeoutSec?: number;
	signal?: AbortSignal;
}): Promise<ApiClientResult> {
	const url = new URL(args.url);
	for (const [key, value] of Object.entries(args.params ?? {})) {
		url.searchParams.set(key, value);
	}
	const method = args.method.toUpperCase();
	const timeoutSec = clampInt(args.timeoutSec ?? 20, 1, 60);
	const headers: Record<string, string> = {
		"User-Agent": SECURITY_SUBAGENT_USER_AGENT,
		...args.headers,
	};
	let body: string | undefined;
	if (args.body !== undefined && args.body !== null && method !== "GET" && method !== "HEAD") {
		body = typeof args.body === "string" ? args.body : JSON.stringify(args.body);
		headers["Content-Type"] ??= "application/json";
	}

	const startedAt = Date.now();
	const response = await fetchWithTimeout(url.toString(), timeoutSec * 1000, args.signal, {
		method,
		headers,
		body,
		redirect: "follow",
	});
	const bodyText = await response.text();
	const contentType = response.headers.get("content-type") ?? "";
	const result: ApiClientResult = {
		url: response.url || url.toString(),
		method,
		statusCode: response.status,
		ok: response.ok,
		contentType,
		elapsedMs: Date.now() - startedAt,
		responseHeaders: Object.fromEntries([...response.headers.entries()].slice(0, 20)),
	};

	const parsed = parseJson(bodyText);
	if (parsed.ok) {
		const serialized = JSON.stringify(parsed.value);
		result.data = serialized.length > 6000 ? truncateJson(parsed.value) : parsed.value;
		result.truncated = serialized.length > 6000;
	} else {
		result.bodyPreview = bodyText.slice(0, 4000);
		result.truncated = bodyText.length > 4000;
	}
	return result;
}

async function searchDuckDuckGo(query: string, maxResults: number, signal?: AbortSignal): Promise<SearchResult[]> {
	const htmlUrl = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
	const html = await fetchText(htmlUrl, SEARCH_TIMEOUT_MS, signal, { "User-Agent": SECURITY_SUBAGENT_USER_AGENT });
	const parsed = parseDuckDuckGoHtml(html, maxResults);
	if (parsed.length > 0) return parsed;
	const liteUrl = `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(query)}`;
	const lite = await fetchText(liteUrl, SEARCH_TIMEOUT_MS, signal, { "User-Agent": SECURITY_SUBAGENT_USER_AGENT });
	return parseDuckDuckGoLite(lite, maxResults);
}

function parseDuckDuckGoHtml(html: string, maxResults: number): SearchResult[] {
	const resultRegex = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
	const snippetRegex = /<a[^>]+class="result__snippet"[^>]*>([\s\S]*?)<\/a>/gi;
	const links: Array<{ url: string; title: string }> = [];
	for (;;) {
		const match = resultRegex.exec(html);
		if (match === null || links.length >= maxResults) break;
		let rawUrl = match[1].trim();
		const uddg = rawUrl.match(/[?&]uddg=([^&]+)/);
		if (uddg) rawUrl = decodeURIComponent(uddg[1]);
		if (!/^https?:\/\//i.test(rawUrl)) continue;
		links.push({ url: rawUrl, title: cleanHtmlToText(match[2]).slice(0, 280) });
	}
	const snippets: string[] = [];
	for (;;) {
		const snippetMatch = snippetRegex.exec(html);
		if (snippetMatch === null || snippets.length >= maxResults) break;
		snippets.push(cleanHtmlToText(snippetMatch[1]).slice(0, 320));
	}
	return links.map((entry, index) => ({ title: entry.title, url: entry.url, snippet: snippets[index] ?? "" }));
}

function parseDuckDuckGoLite(html: string, maxResults: number): SearchResult[] {
	const linkRegex = /<a[^>]+rel="nofollow"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
	const snippetRegex = /<td[^>]*class="result-snippet"[^>]*>([\s\S]*?)<\/td>/gi;
	const links: Array<{ url: string; title: string }> = [];
	for (;;) {
		const linkMatch = linkRegex.exec(html);
		if (linkMatch === null || links.length >= maxResults) break;
		const rawUrl = linkMatch[1].trim();
		if (!/^https?:\/\//i.test(rawUrl)) continue;
		links.push({ url: rawUrl, title: cleanHtmlToText(linkMatch[2]).slice(0, 280) });
	}
	const snippets: string[] = [];
	for (;;) {
		const snippetMatch = snippetRegex.exec(html);
		if (snippetMatch === null || snippets.length >= maxResults) break;
		snippets.push(cleanHtmlToText(snippetMatch[1]).slice(0, 320));
	}
	return links.map((entry, index) => ({ title: entry.title, url: entry.url, snippet: snippets[index] ?? "" }));
}

async function fetchSearchPages(results: SearchResult[], signal?: AbortSignal): Promise<SearchResult[]> {
	const out: SearchResult[] = [];
	for (const result of results) {
		try {
			const page = await pageExtract({ url: result.url, mode: "text", signal });
			out.push({ ...result, pageContent: page.content?.slice(0, 1500) ?? "" });
		} catch {
			out.push(result);
		}
	}
	return out;
}

async function crawlOnePage(
	url: string,
	depth: number,
	signal?: AbortSignal,
): Promise<{ ok: true; page: CrawlPage } | { ok: false; error: string }> {
	try {
		const robots = await isAllowedByRobots(url, signal);
		if (!robots.allowed) return { ok: false, error: `Blocked by robots.txt: ${robots.reason}` };
		await rateLimitWait(url, robots.crawlDelaySec);
		const page = await fetchHtmlPage(url, PAGE_FETCH_TIMEOUT_MS, signal);
		const content = cleanHtmlToText(page.html);
		const links = extractLinks(page.html, page.url, 30);
		return {
			ok: true,
			page: {
				url: page.url,
				depth,
				title: page.title,
				contentPreview: content.slice(0, 900),
				contentLength: content.length,
				linksFound: links.length,
				links,
			},
		};
	} catch (error) {
		return { ok: false, error: error instanceof Error ? error.message : String(error) };
	}
}

async function fetchHtmlPage(
	url: string,
	timeoutMs: number,
	signal?: AbortSignal,
): Promise<{ url: string; html: string; title: string }> {
	const response = await fetchWithTimeout(url, timeoutMs, signal, {
		redirect: "follow",
		headers: {
			"User-Agent": SECURITY_SUBAGENT_USER_AGENT,
			Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
		},
	});
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
	const contentType = response.headers.get("content-type") ?? "";
	if (contentType && !/text\/html|application\/xhtml\+xml/i.test(contentType)) {
		throw new Error(`Unsupported content type: ${contentType}`);
	}
	const html = await response.text();
	return { url: response.url || url, html, title: extractTitle(html) };
}

async function fetchText(
	url: string,
	timeoutMs: number,
	signal?: AbortSignal,
	headers?: Record<string, string>,
): Promise<string> {
	const response = await fetchWithTimeout(url, timeoutMs, signal, { redirect: "follow", headers });
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
	return response.text();
}

async function fetchWithTimeout(
	url: string,
	timeoutMs: number,
	signal: AbortSignal | undefined,
	init: RequestInit,
): Promise<Response> {
	const controller = new AbortController();
	const abort = () => controller.abort();
	signal?.addEventListener("abort", abort, { once: true });
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		return await fetch(url, { ...init, signal: controller.signal });
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", abort);
	}
}

function normalizeHttpUrl(raw: string): string {
	const url = new URL(raw.trim());
	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new Error("Only http/https URLs are allowed");
	}
	return url.toString();
}

function parseJson(text: string): { ok: true; value: unknown } | { ok: false } {
	try {
		return { ok: true, value: JSON.parse(text) };
	} catch {
		return { ok: false };
	}
}

function truncateJson(value: unknown): unknown {
	if (Array.isArray(value)) return { items: value.slice(0, 20), total_items_observed: value.length };
	if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).slice(0, 40));
	return value;
}

function clampInt(raw: number, min: number, max: number): number {
	if (!Number.isFinite(raw)) return min;
	return Math.min(max, Math.max(min, Math.floor(raw)));
}
