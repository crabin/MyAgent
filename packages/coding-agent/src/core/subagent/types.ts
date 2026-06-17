export type SecurityDedicatedSubagentName = "asset_discovery" | "attack_surface_analysis" | "poc_research";

export interface SecurityDedicatedSubagentModel {
	name: SecurityDedicatedSubagentName;
	displayName: string;
	role: "asset_discovery_agent" | "attack_surface_analysis_agent" | "poc_research_agent";
	mission: string;
	focus: string[];
	requiredInputs: string[];
	produces: string[];
	boundaries: string[];
}

export interface SecurityDedicatedSubagentMemoryContract {
	namespace: SecurityDedicatedSubagentName;
	remember: string[];
	recall: string[];
	handoff: string[];
}

export interface SecurityDedicatedSubagentToolContract {
	requiredTools: string[];
	optionalTools: string[];
	externalMethods: string[];
	toolCalls?: SecurityDedicatedSubagentToolCall[];
	externalToolCalls?: SecurityDedicatedSubagentExternalToolCall[];
}

export interface SecurityDedicatedSubagentToolParameter {
	name: string;
	required: boolean;
	description: string;
	source: string;
}

export interface SecurityDedicatedSubagentToolCall {
	tool: string;
	label: string;
	description: string;
	required: boolean;
	promptSnippet: string;
	promptGuidelines: string[];
	parameters: SecurityDedicatedSubagentToolParameter[];
	inputsNeeded: string[];
	expectedOutput: string;
	useWhen: string;
	safetyConstraints: string[];
	nextStepUse: string;
}

export interface SecurityDedicatedSubagentExternalToolCall {
	method: string;
	category: "user_supplied" | "passive_osint" | "external_platform" | "authorized_terminal" | "cloud_inventory";
	required: boolean;
	inputsNeeded: string[];
	expectedOutput: string;
	useWhen: string;
	prompt: string;
	safetyConstraints: string[];
}

export interface SecurityDedicatedSubagentPromptContract {
	systemPrompt: string;
	handoffPrompt: string;
}

export interface SecurityDedicatedSubagentDefinition {
	name: SecurityDedicatedSubagentName;
	displayName: string;
	mission: string;
	focus: string[];
	requiredInputs: string[];
	produces: string[];
	boundaries: string[];
	model: SecurityDedicatedSubagentModel;
	memory: SecurityDedicatedSubagentMemoryContract;
	tools: SecurityDedicatedSubagentToolContract;
	prompt: SecurityDedicatedSubagentPromptContract;
}
