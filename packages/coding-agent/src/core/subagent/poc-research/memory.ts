import type { SecurityDedicatedSubagentMemoryContract } from "../types.ts";

export const POC_RESEARCH_MEMORY: SecurityDedicatedSubagentMemoryContract = {
	namespace: "poc_research",
	remember: [
		"service and middleware evidence used for PoC research",
		"candidate CVEs and vulnerability database records",
		"public PoC references and confidence caveats",
		"defensive findings and report inputs",
	],
	recall: [
		"attack surface map",
		"observed services and middleware",
		"product/version evidence",
		"prior PoC research notes",
	],
	handoff: [
		"PoC availability notes",
		"candidate references",
		"defensive exploitability caveats",
		"findings for vulnerability assessment and report generation",
	],
};
