import type { SecurityDedicatedSubagentMemoryContract } from "../types.ts";

export const ASSET_DISCOVERY_MEMORY: SecurityDedicatedSubagentMemoryContract = {
	namespace: "asset_discovery",
	remember: [
		"authorized target list and exclusions",
		"asset inventory with source attribution",
		"live host and open service observations",
		"coverage gaps and recommended next discovery checks",
	],
	recall: ["prior target scope", "previous asset inventory", "known exclusions", "approved port scope"],
	handoff: [
		"asset inventory",
		"live hosts and open services",
		"source references",
		"coverage gaps for attack surface analysis",
	],
};
