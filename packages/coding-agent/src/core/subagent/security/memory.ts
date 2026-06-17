import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export type SecurityMemoryType = "short_term" | "episodic" | "long_term";

export interface SecurityMemoryItem {
	id: string;
	content: string;
	type: SecurityMemoryType;
	importance: number;
	metadata: Record<string, unknown>;
	createdAt: string;
}

export interface SecurityContextBlock {
	contextBlock: string;
	debug: {
		shortTermCount: number;
		episodicCount: number;
		longTermCount: number;
		selectedCount: number;
		usedTokensEstimate: number;
		budgetTokens: number;
	};
}

export interface SecurityMemoryPersistenceResult {
	path: string;
	itemCount: number;
	stats: { shortTermCount: number; episodicCount: number; longTermCount: number };
}

export interface SecurityMemoryStore {
	remember(input: {
		content: string;
		type?: SecurityMemoryType;
		importance?: number;
		metadata?: Record<string, unknown>;
		now?: Date;
	}): SecurityMemoryItem;
	recall(input?: { query?: string; type?: SecurityMemoryType; limit?: number }): SecurityMemoryItem[];
	context(input?: { query?: string; budgetTokens?: number }): SecurityContextBlock;
	stats(): { shortTermCount: number; episodicCount: number; longTermCount: number };
	saveToFile(path: string): SecurityMemoryPersistenceResult;
	loadFromFile(path: string): SecurityMemoryPersistenceResult;
	clear(type?: SecurityMemoryType): void;
}

const SHORT_TERM_MAX_ITEMS = 20;
const DEFAULT_CONTEXT_BUDGET = 1200;

export function createSecurityMemoryStore(): SecurityMemoryStore {
	let shortTerm: SecurityMemoryItem[] = [];
	let episodic: SecurityMemoryItem[] = [];
	let longTerm: SecurityMemoryItem[] = [];

	const itemsForType = (type: SecurityMemoryType): SecurityMemoryItem[] => {
		if (type === "short_term") return shortTerm;
		if (type === "episodic") return episodic;
		return longTerm;
	};

	const setItemsForType = (type: SecurityMemoryType, items: SecurityMemoryItem[]): void => {
		if (type === "short_term") {
			shortTerm = items;
		} else if (type === "episodic") {
			episodic = items;
		} else {
			longTerm = items;
		}
	};

	return {
		remember(input) {
			const content = input.content.trim();
			if (!content) {
				throw new Error("memory content is required.");
			}
			const type = input.type ?? "short_term";
			const item: SecurityMemoryItem = {
				id: randomUUID(),
				content,
				type,
				importance: clampImportance(input.importance ?? 0.5),
				metadata: input.metadata ?? {},
				createdAt: (input.now ?? new Date()).toISOString(),
			};
			const next = [...itemsForType(type), item];
			setItemsForType(type, type === "short_term" ? next.slice(-SHORT_TERM_MAX_ITEMS) : next);
			return item;
		},
		recall(input = {}) {
			const limit = clampLimit(input.limit ?? 8);
			const candidates = input.type ? itemsForType(input.type) : [...shortTerm, ...episodic, ...longTerm];
			const query = input.query?.trim().toLowerCase() ?? "";
			const scored = candidates
				.map((item) => ({ item, score: scoreMemory(item, query) }))
				.filter((entry) => entry.score > 0)
				.sort((a, b) => b.score - a.score || b.item.createdAt.localeCompare(a.item.createdAt));
			return scored.slice(0, limit).map((entry) => entry.item);
		},
		context(input = {}) {
			const budgetTokens = clampBudget(input.budgetTokens ?? DEFAULT_CONTEXT_BUDGET);
			const recalled = this.recall({ query: input.query, limit: 30 });
			const selected: SecurityMemoryItem[] = [];
			let usedTokensEstimate = 0;

			for (const item of recalled) {
				const tokens = approxTokens(item.content);
				if (usedTokensEstimate + tokens > budgetTokens && selected.length > 0) break;
				selected.push(item);
				usedTokensEstimate += tokens;
			}

			const contextBlock = renderContextBlock(selected);
			return {
				contextBlock,
				debug: {
					shortTermCount: shortTerm.length,
					episodicCount: episodic.length,
					longTermCount: longTerm.length,
					selectedCount: selected.length,
					usedTokensEstimate,
					budgetTokens,
				},
			};
		},
		stats() {
			return {
				shortTermCount: shortTerm.length,
				episodicCount: episodic.length,
				longTermCount: longTerm.length,
			};
		},
		saveToFile(path) {
			const snapshot = {
				version: 1,
				items: [...shortTerm, ...episodic, ...longTerm],
			};
			const dir = dirname(path);
			if (!existsSync(dir)) {
				mkdirSync(dir, { recursive: true });
			}
			writeFileSync(path, JSON.stringify(snapshot, null, 2), { encoding: "utf-8", mode: 0o600 });
			return { path, itemCount: snapshot.items.length, stats: this.stats() };
		},
		loadFromFile(path) {
			if (!existsSync(path)) {
				return { path, itemCount: 0, stats: this.stats() };
			}
			const raw = JSON.parse(readFileSync(path, "utf-8")) as unknown;
			const items = readSnapshotItems(raw);
			for (const item of items) {
				const existing = itemsForType(item.type).some((candidate) => candidate.id === item.id);
				if (!existing) {
					setItemsForType(item.type, [...itemsForType(item.type), item]);
				}
			}
			shortTerm = shortTerm.slice(-SHORT_TERM_MAX_ITEMS);
			return { path, itemCount: items.length, stats: this.stats() };
		},
		clear(type) {
			if (!type) {
				shortTerm = [];
				episodic = [];
				longTerm = [];
				return;
			}
			setItemsForType(type, []);
		},
	};
}

function scoreMemory(item: SecurityMemoryItem, query: string): number {
	const recency = Date.parse(item.createdAt) / 1_000_000_000_000;
	const base = item.importance + recency;
	if (!query) return base;
	const semanticScore = cosineSimilarity(
		termVector(query),
		termVector(`${item.content} ${JSON.stringify(item.metadata)}`),
	);
	return semanticScore === 0 ? 0 : base + semanticScore * 4;
}

function renderContextBlock(items: SecurityMemoryItem[]): string {
	if (items.length === 0) return "";
	const sections: Array<{ title: string; type: SecurityMemoryType }> = [
		{ title: "Recent Security Context", type: "short_term" },
		{ title: "Past Security Episodes", type: "episodic" },
		{ title: "Security Knowledge", type: "long_term" },
	];
	const lines = ["Security Memory Context"];
	for (const section of sections) {
		const scoped = items.filter((item) => item.type === section.type);
		if (scoped.length === 0) continue;
		lines.push("", `[${section.title}]`);
		for (const item of scoped) {
			lines.push(`- ${item.content}`);
		}
	}
	return lines.join("\n");
}

function approxTokens(text: string): number {
	return Math.max(1, Math.ceil(text.length / 4));
}

function clampImportance(value: number): number {
	if (!Number.isFinite(value)) return 0.5;
	return Math.min(1, Math.max(0, value));
}

function clampLimit(value: number): number {
	if (!Number.isFinite(value)) return 8;
	return Math.min(50, Math.max(1, Math.trunc(value)));
}

function clampBudget(value: number): number {
	if (!Number.isFinite(value)) return DEFAULT_CONTEXT_BUDGET;
	return Math.min(8000, Math.max(100, Math.trunc(value)));
}

function readSnapshotItems(value: unknown): SecurityMemoryItem[] {
	const root = readObject(value);
	const rawItems = Array.isArray(root.items) ? root.items : [];
	return rawItems.map(readMemoryItem).filter((item): item is SecurityMemoryItem => item !== undefined);
}

function readMemoryItem(value: unknown): SecurityMemoryItem | undefined {
	const item = readObject(value);
	const id = readString(item.id);
	const content = readString(item.content);
	const type = readMemoryType(item.type);
	const createdAt = readString(item.createdAt);
	if (!id || !content || !type || !createdAt) return undefined;
	return {
		id,
		content,
		type,
		importance: clampImportance(readNumber(item.importance) ?? 0.5),
		metadata: readObject(item.metadata),
		createdAt,
	};
}

function termVector(text: string): Map<string, number> {
	const vector = new Map<string, number>();
	for (const term of text.toLowerCase().match(/[\p{L}\p{N}_.:-]+/gu) ?? []) {
		if (term.length < 2) continue;
		vector.set(term, (vector.get(term) ?? 0) + 1);
	}
	return vector;
}

function cosineSimilarity(left: Map<string, number>, right: Map<string, number>): number {
	if (left.size === 0 || right.size === 0) return 0;
	let dot = 0;
	let leftMagnitude = 0;
	let rightMagnitude = 0;
	for (const value of left.values()) {
		leftMagnitude += value * value;
	}
	for (const [term, value] of right.entries()) {
		rightMagnitude += value * value;
		dot += (left.get(term) ?? 0) * value;
	}
	if (leftMagnitude === 0 || rightMagnitude === 0) return 0;
	return dot / Math.sqrt(leftMagnitude * rightMagnitude);
}

function readObject(value: unknown): Record<string, unknown> {
	return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function readString(value: unknown): string {
	return typeof value === "string" ? value : "";
}

function readNumber(value: unknown): number | undefined {
	return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function readMemoryType(value: unknown): SecurityMemoryType | undefined {
	return value === "short_term" || value === "episodic" || value === "long_term" ? value : undefined;
}
