import type { SecurityDedicatedSubagentMemoryContract } from "../types.ts";

export const ATTACK_SURFACE_ANALYSIS_MEMORY: SecurityDedicatedSubagentMemoryContract = {
	namespace: "attack_surface_analysis",
	remember: [
		"attack surface map",
		"observed technologies and service fingerprints",
		"HTTP endpoints, routes, forms, and API metadata",
		"authentication boundaries and evidence gaps",
	],
	recall: ["asset discovery output", "open ports", "prior service fingerprints", "known HTTP endpoints"],
	handoff: [
		"services and middleware",
		"product/version evidence",
		"HTTP/API entry points",
		"configuration observations for PoC research",
	],
};
