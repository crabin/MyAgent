const ENTITY_MAP: Record<string, string> = {
	"&amp;": "&",
	"&lt;": "<",
	"&gt;": ">",
	"&quot;": '"',
	"&#39;": "'",
	"&nbsp;": " ",
};

export interface LinkItem {
	text: string;
	url: string;
}

export interface ImageItem {
	alt: string;
	src: string;
}

function decodeEntity(entity: string): string {
	if (ENTITY_MAP[entity]) return ENTITY_MAP[entity];
	if (/^&#\d+;$/.test(entity)) {
		const code = Number(entity.slice(2, -1));
		return Number.isFinite(code) ? String.fromCodePoint(code) : entity;
	}
	if (/^&#x[0-9a-f]+;$/i.test(entity)) {
		const code = Number.parseInt(entity.slice(3, -1), 16);
		return Number.isFinite(code) ? String.fromCodePoint(code) : entity;
	}
	return entity;
}

export function decodeHtmlEntities(input: string): string {
	return input.replace(/&(?:amp|lt|gt|quot|#39|nbsp);|&#\d+;|&#x[0-9a-f]+;/gi, (entity) => decodeEntity(entity));
}

export function stripTags(input: string): string {
	return decodeHtmlEntities(input.replace(/<[^>]+>/g, " "));
}

export function normalizeText(input: string): string {
	return input
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.join("\n");
}

export function cleanHtmlToText(html: string): string {
	const cleaned = html
		.replace(/<!--[\s\S]*?-->/g, " ")
		.replace(/<script[\s\S]*?<\/script>/gi, " ")
		.replace(/<style[\s\S]*?<\/style>/gi, " ")
		.replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
		.replace(/<nav[\s\S]*?<\/nav>/gi, " ")
		.replace(/<footer[\s\S]*?<\/footer>/gi, " ")
		.replace(/<header[\s\S]*?<\/header>/gi, " ")
		.replace(/<aside[\s\S]*?<\/aside>/gi, " ")
		.replace(/<iframe[\s\S]*?<\/iframe>/gi, " ");
	const text = stripTags(cleaned)
		.replace(/[ \t]+\n/g, "\n")
		.replace(/\n{3,}/g, "\n\n");
	return normalizeText(text);
}

export function extractTitle(html: string): string {
	const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
	return match ? stripTags(match[1]).trim().slice(0, 500) : "";
}

export function extractLinks(html: string, baseUrl?: string, limit = 20): LinkItem[] {
	const links: LinkItem[] = [];
	const seen = new Set<string>();
	const regex = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

	for (;;) {
		const match = regex.exec(html);
		if (match === null || links.length >= limit) break;
		const href = safeAbsoluteUrl(match[1], baseUrl);
		if (!href || seen.has(href)) continue;
		seen.add(href);
		const text = stripTags(match[2]).trim().slice(0, 120);
		if (!text) continue;
		links.push({ text, url: href });
	}

	return links;
}

export function extractImages(html: string, baseUrl?: string, limit = 10): ImageItem[] {
	const images: ImageItem[] = [];
	const seen = new Set<string>();
	const regex = /<img\b([^>]*?)>/gi;
	for (;;) {
		const match = regex.exec(html);
		if (match === null || images.length >= limit) break;
		const attrs = match[1];
		const srcMatch = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
		if (!srcMatch) continue;
		const src = safeAbsoluteUrl(srcMatch[1], baseUrl);
		if (!src || seen.has(src)) continue;
		seen.add(src);
		const alt = stripTags((attrs.match(/\balt\s*=\s*["']([^"']*)["']/i)?.[1] ?? "").trim()).slice(0, 120);
		images.push({ alt, src });
	}
	return images;
}

export function extractHeadings(html: string, limit = 50): Array<{ level: number; text: string }> {
	const headings: Array<{ level: number; text: string }> = [];
	const regex = /<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi;

	for (;;) {
		const match = regex.exec(html);
		if (match === null || headings.length >= limit) break;
		const level = Number(match[1]);
		const text = stripTags(match[2]).trim();
		if (text) headings.push({ level, text: text.slice(0, 220) });
	}

	return headings;
}

export function extractMetaTags(html: string, limit = 20): Record<string, string> {
	const meta: Record<string, string> = {};
	const regex = /<meta\b[^>]*>/gi;
	for (;;) {
		const match = regex.exec(html);
		if (match === null) break;
		const tag = match[0];
		const key =
			tag.match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1] ?? tag.match(/\bproperty\s*=\s*["']([^"']+)["']/i)?.[1];
		const content = tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1] ?? "";
		if (!key || !content) continue;
		if (!(key in meta)) {
			meta[key] = decodeHtmlEntities(content).slice(0, 500);
			if (Object.keys(meta).length >= limit) break;
		}
	}
	return meta;
}

export function applySimpleSelector(html: string, selector?: string): string {
	if (!selector) return html;
	const s = selector.trim();
	if (!s) return html;
	if (/^[a-z][a-z0-9-]*$/i.test(s)) {
		const blocks = extractContainer(html, new RegExp(`<${s}\\b[^>]*>[\\s\\S]*?<\\/${s}>`, "gi"));
		return blocks.length > 0 ? blocks.join("\n") : html;
	}
	if (/^#[a-zA-Z0-9\-_]+$/.test(s)) {
		const id = escapeRegex(s.slice(1));
		const blocks = extractContainer(
			html,
			new RegExp(`<([a-z0-9]+)\\b[^>]*\\bid=["']${id}["'][^>]*>[\\s\\S]*?<\\/\\1>`, "gi"),
		);
		return blocks.length > 0 ? blocks.join("\n") : html;
	}
	if (/^\.[a-zA-Z0-9\-_]+$/.test(s)) {
		const cls = escapeRegex(s.slice(1));
		const blocks = extractContainer(
			html,
			new RegExp(`<([a-z0-9]+)\\b[^>]*\\bclass=["'][^"']*\\b${cls}\\b[^"']*["'][^>]*>[\\s\\S]*?<\\/\\1>`, "gi"),
		);
		return blocks.length > 0 ? blocks.join("\n") : html;
	}
	return html;
}

export function normalizeUrlForVisit(url: string): string {
	try {
		const u = new URL(url);
		u.hash = "";
		let normalized = u.toString();
		if (normalized.endsWith("/")) normalized = normalized.slice(0, -1);
		return normalized;
	} catch {
		return url.trim();
	}
}

function safeAbsoluteUrl(raw: string, baseUrl?: string): string {
	const candidate = raw.trim();
	if (!candidate) return "";
	if (/^(javascript:|mailto:|tel:|#)/i.test(candidate)) return "";
	try {
		return baseUrl ? new URL(candidate, baseUrl).toString() : new URL(candidate).toString();
	} catch {
		return "";
	}
}

function escapeRegex(input: string): string {
	return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractContainer(html: string, pattern: RegExp): string[] {
	const blocks: string[] = [];
	for (;;) {
		const match = pattern.exec(html);
		if (match === null) break;
		blocks.push(match[0]);
	}
	return blocks;
}
