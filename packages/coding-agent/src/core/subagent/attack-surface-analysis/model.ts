import type { SecurityDedicatedSubagentModel } from "../types.ts";

export const ATTACK_SURFACE_ANALYSIS_MODEL: SecurityDedicatedSubagentModel = {
	name: "attack_surface_analysis",
	displayName: "Attack Surface Analysis Subagent",
	role: "attack_surface_analysis_agent",
	mission:
		"Convert the asset inventory into exposed services, technologies, authentication boundaries, URLs, APIs, and likely entry points.",
	focus: ["service fingerprints", "HTTP headers", "routes", "forms", "APIs", "authentication boundaries"],
	requiredInputs: ["asset discovery output", "open ports", "HTTP endpoints", "technology fingerprints"],
	produces: ["attack surface map", "technology/service inventory", "entry points", "evidence gaps"],
	boundaries: [
		"Do not decide PoC exploitability.",
		"Do not execute payloads or scanner commands unless separately authorized and reviewed.",
		"Treat fingerprints as evidence with confidence, not certainty.",
	],
};
