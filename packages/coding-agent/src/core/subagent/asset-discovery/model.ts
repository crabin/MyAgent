import type { SecurityDedicatedSubagentModel } from "../types.ts";

export const ASSET_DISCOVERY_MODEL: SecurityDedicatedSubagentModel = {
	name: "asset_discovery",
	displayName: "Asset Discovery Subagent",
	role: "asset_discovery_agent",
	mission:
		"Build the authorized asset baseline from supplied scope, passive sources, DNS/API metadata, and bounded authorized discovery.",
	focus: ["domains", "hosts", "URLs", "CIDRs", "cloud or third-party exposure", "open services"],
	requiredInputs: ["authorized targets", "test window", "out-of-scope assets", "approved port scope"],
	produces: ["asset inventory", "live host/service observations", "source references", "coverage gaps"],
	boundaries: [
		"Do not analyze exploitability or PoC viability.",
		"Do not broaden targets beyond the explicit authorization scope.",
		"Do not perform active checks before authorization is confirmed.",
	],
};
