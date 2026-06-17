export type SecurityPayloadTask =
	| "http_request"
	| "injection_probe"
	| "scanner_command"
	| "manual_validation"
	| "safe_proof_of_impact";

export interface SecurityPayloadModelConfig {
	provider: string;
	model: string;
	thinkingLevel: "off" | "minimal" | "low";
	maxTokens: number;
	temperature: number;
	purpose: string;
	fallback: {
		mode: "current_main_model";
		reason: string;
	};
}

export interface SecurityPayloadPromptInput {
	task: SecurityPayloadTask;
	objective: string;
	targets: string[];
	authorizedActions: string[];
	constraints?: string[];
	evidence?: string[];
}

export interface SecurityPayloadPrompt {
	modelConfig: SecurityPayloadModelConfig;
	systemPrompt: string;
	userPrompt: string;
	fallbackPrompt: string;
	reviewRequirements: string[];
}

export const SECURITY_PAYLOAD_MODEL_CONFIG: SecurityPayloadModelConfig = {
	provider: "security-payload-local",
	model: "security-payload-generator-small",
	thinkingLevel: "off",
	maxTokens: 1200,
	temperature: 0.1,
	purpose: "Generate bounded defensive security payload or command candidates for main-model review.",
	fallback: {
		mode: "current_main_model",
		reason:
			"If the dedicated small payload model is unavailable, not configured, or fails, the current main model must generate the same bounded candidates from fallbackPrompt and continue the workflow.",
	},
};

export function buildSecurityPayloadPrompt(input: SecurityPayloadPromptInput): SecurityPayloadPrompt {
	const targets = normalizeList(input.targets);
	if (targets.length === 0) {
		throw new Error("At least one authorized target is required for payload generation.");
	}
	const authorizedActions = normalizeList(input.authorizedActions);
	if (authorizedActions.length === 0) {
		throw new Error("At least one authorized action category is required for payload generation.");
	}
	const constraints = normalizeList(input.constraints ?? []);
	const evidence = normalizeList(input.evidence ?? []);
	const systemPrompt = [
		"You are the security payload generator for an authorized defensive assessment.",
		"Generate only bounded payload or command candidates that fit the provided targets, allowed actions, and constraints.",
		"Do not include persistence, credential theft, destructive actions, data exfiltration, lateral movement, stealth, malware, reverse shells, or remote-control behavior.",
		"Prefer harmless proof strings, metadata-only checks, read-only commands, dry-run flags, low rate limits, and clear rollback notes.",
		"Return JSON with fields: task, candidates, assumptions, safety_checks, and main_model_review_notes.",
	].join("\n");
	const userPrompt = [
		`Task: ${input.task}`,
		`Objective: ${input.objective.trim()}`,
		`Authorized targets: ${targets.join(", ")}`,
		`Authorized actions: ${authorizedActions.join(", ")}`,
		constraints.length > 0
			? `Constraints: ${constraints.join("; ")}`
			: "Constraints: use the least intrusive validation possible.",
		evidence.length > 0 ? `Evidence: ${evidence.join("; ")}` : "Evidence: none supplied.",
		"Generate candidates only. Do not claim they were executed.",
	].join("\n");
	const fallbackPrompt = [
		"Dedicated small payload model unavailable or skipped.",
		"Main model fallback instruction: generate the same bounded candidate JSON yourself using the systemPrompt and userPrompt above.",
		"Continue the workflow without failing, but preserve all authorization, scope, target, duration, port, and safety review requirements.",
		"Do not execute or recommend execution until the candidate is reviewed against active authorization.",
	].join("\n");
	return {
		modelConfig: SECURITY_PAYLOAD_MODEL_CONFIG,
		systemPrompt,
		userPrompt,
		fallbackPrompt,
		reviewRequirements: [
			"Main model must verify active user authorization before using any candidate.",
			"Main model must reject candidates outside target, action, duration, or port scope.",
			"If the small payload model is unavailable, the main model must use fallbackPrompt and continue without interrupting the workflow.",
			"Main model must explain the next command or payload before execution and ask for approval for expanded scope.",
		],
	};
}

function normalizeList(values: string[]): string[] {
	return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
