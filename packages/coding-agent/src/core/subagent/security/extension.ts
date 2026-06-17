import type {
	AgentEndEvent,
	BeforeAgentStartEvent,
	BeforeAgentStartEventResult,
	ExtensionContext,
	ExtensionFactory,
} from "../../extensions/index.ts";
import { createSecurityAuthorizationStore } from "./authorization.ts";
import { classifySecurityIntent, type SecurityIntentDecision } from "./intent-router.ts";
import { createSecurityMemoryStore } from "./memory.ts";
import { buildSecuritySubagentPrompt } from "./prompt.ts";
import { getSecurityMemoryPath } from "./session-memory.ts";
import { createSecurityTerminalManager } from "./terminal-session.ts";
import { createSecuritySubagentTools } from "./tools.ts";

export const createSecuritySubagentExtension: ExtensionFactory = (pi) => {
	const authorization = createSecurityAuthorizationStore();
	const terminal = createSecurityTerminalManager();
	const memory = createSecurityMemoryStore();
	let loadedMemoryPath: string | undefined;
	for (const tool of createSecuritySubagentTools(authorization, terminal, memory)) {
		pi.registerTool(tool);
	}

	pi.on(
		"before_agent_start",
		async (event: BeforeAgentStartEvent, ctx: ExtensionContext): Promise<BeforeAgentStartEventResult | undefined> => {
			loadedMemoryPath = loadSessionMemory(memory, ctx, loadedMemoryPath);
			let decision = classifySecurityIntent(event.prompt);
			const continuation = isSecurityContinuationRequest(event.prompt);
			if (
				decision.intent === "not_security" &&
				continuation &&
				memory.stats().episodicCount + memory.stats().shortTermCount > 0
			) {
				decision = buildContinuationDecision(event.prompt);
			}
			if (decision.intent === "not_security") {
				return undefined;
			}

			memory.remember({
				content: `User security request: ${event.prompt}`,
				type: "short_term",
				importance: 0.6,
				metadata: { intent: decision.intent, focus: decision.focus },
			});
			const memoryContext = memory.context({ query: event.prompt, budgetTokens: 1200 });
			const subagentPrompt = buildSecuritySubagentPrompt(decision);
			const contextPrompt = renderSecurityContextPrompt(memoryContext.contextBlock, memoryContext.debug);
			const fullPrompt = contextPrompt ? `${subagentPrompt}\n\n${contextPrompt}` : subagentPrompt;
			return {
				message: {
					customType: "security_subagent",
					content: fullPrompt,
					display: true,
					details: {
						decision,
						contextUsage: memoryContext.debug,
					},
				},
				systemPrompt: `${event.systemPrompt}\n\n${fullPrompt}`,
			};
		},
	);

	pi.on("agent_end", async (event: AgentEndEvent, ctx: ExtensionContext) => {
		const summary = summarizeSecurityTurn(event);
		if (!summary) return;
		memory.remember({
			content: summary,
			type: "episodic",
			importance: 0.75,
			metadata: { kind: "security_turn_summary" },
		});
		loadedMemoryPath = loadSessionMemory(memory, ctx, loadedMemoryPath);
		memory.saveToFile(getSecurityMemoryPath(ctx));
	});
};

function loadSessionMemory(
	memory: ReturnType<typeof createSecurityMemoryStore>,
	ctx: ExtensionContext,
	loadedMemoryPath: string | undefined,
): string {
	const path = getSecurityMemoryPath(ctx);
	if (loadedMemoryPath !== path) {
		memory.loadFromFile(path);
	}
	return path;
}

function isSecurityContinuationRequest(prompt: string): boolean {
	const normalized = prompt.trim().toLowerCase();
	return [
		"继续",
		"继续执行",
		"下一步",
		"接着",
		"接着做",
		"继续下一步",
		"continue",
		"go on",
		"next",
		"next step",
	].includes(normalized);
}

function buildContinuationDecision(prompt: string): SecurityIntentDecision {
	return {
		intent: "security_task_complex",
		confidence: 0.74,
		needsAuthorization: true,
		needsExplore: true,
		needsReport: true,
		focus: [],
		rationale: `Short continuation request (${prompt.trim()}) matched recent security memory; use memory context to recover the prior target without expanding scope.`,
	};
}

function summarizeSecurityTurn(event: AgentEndEvent): string | undefined {
	if (!event.messages.some((message) => message.role === "custom" && message.customType === "security_subagent")) {
		return undefined;
	}
	const userText = lastMessageText(event.messages, "user");
	const assistantText = lastMessageText(event.messages, "assistant");
	const assistantSummary = assistantText ? assistantText.slice(0, 1200).replace(/\s+/g, " ").trim() : "";
	if (!userText && !assistantSummary) return undefined;
	return [
		userText ? `Previous security request: ${userText.slice(0, 400).replace(/\s+/g, " ").trim()}.` : "",
		assistantSummary ? `Previous security conclusion/next step: ${assistantSummary}.` : "",
		"Short continuation requests should use this context to recover the prior target, but any new target or broader authorization still requires explicit user confirmation.",
	]
		.filter(Boolean)
		.join(" ");
}

function lastMessageText(messages: AgentEndEvent["messages"], role: "user" | "assistant"): string | undefined {
	for (let index = messages.length - 1; index >= 0; index--) {
		const message = messages[index];
		if (message?.role !== role) continue;
		const text = extractTextContent(message.content);
		if (text) return text;
	}
	return undefined;
}

function extractTextContent(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((part) => {
			if (typeof part !== "object" || part === null) return "";
			const record = part as { type?: unknown; text?: unknown };
			return record.type === "text" && typeof record.text === "string" ? record.text : "";
		})
		.filter(Boolean)
		.join("\n");
}

function renderSecurityContextPrompt(
	contextBlock: string,
	debug: {
		selectedCount: number;
		usedTokensEstimate: number;
		budgetTokens: number;
		shortTermCount: number;
		episodicCount: number;
		longTermCount: number;
	},
): string {
	const usage = [
		"Security Context Usage",
		`Selected memories: ${debug.selectedCount}`,
		`Estimated tokens: ${debug.usedTokensEstimate}/${debug.budgetTokens}`,
		`Memory counts: short_term=${debug.shortTermCount}, episodic=${debug.episodicCount}, long_term=${debug.longTermCount}`,
	].join("\n");
	return contextBlock ? `${contextBlock}\n\n${usage}` : usage;
}
