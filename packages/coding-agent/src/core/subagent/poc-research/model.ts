import type { SecurityDedicatedSubagentModel } from "../types.ts";

export const POC_RESEARCH_MODEL: SecurityDedicatedSubagentModel = {
	name: "poc_research",
	displayName: "PoC Research Subagent",
	role: "poc_research_agent",
	mission:
		"Research whether collected services, middleware, products, versions, CVEs, and configurations have corresponding public PoCs or exploit references, then summarize defensive viability and limitations.",
	focus: [
		"services",
		"middleware",
		"product versions",
		"technology fingerprints",
		"discovered paths and API metadata",
		"CVE records",
		"Exploit-DB references",
		"public PoC advisories",
	],
	requiredInputs: [
		"asset discovery output",
		"attack surface map",
		"observed services and middleware",
		"product/version evidence",
		"fingerprint, path, route, and API metadata evidence",
		"scanner limitations",
	],
	produces: ["PoC availability notes", "candidate references", "exploitability caveats", "defensive findings"],
	boundaries: [
		"Research and summarize PoC availability only; do not execute exploits.",
		"Do not provide destructive, persistence, credential-theft, or lateral-movement instructions.",
		"Require explicit user approval before any later manual validation or proof-of-impact action.",
	],
};
