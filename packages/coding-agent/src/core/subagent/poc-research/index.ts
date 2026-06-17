import type { SecurityDedicatedSubagentDefinition } from "../types.ts";
import { POC_RESEARCH_MEMORY } from "./memory.ts";
import { POC_RESEARCH_MODEL } from "./model.ts";
import { POC_RESEARCH_PROMPT } from "./prompt.ts";
import { POC_RESEARCH_TOOLS } from "./tools.ts";

export const POC_RESEARCH_SUBAGENT: SecurityDedicatedSubagentDefinition = {
	...POC_RESEARCH_MODEL,
	model: POC_RESEARCH_MODEL,
	memory: POC_RESEARCH_MEMORY,
	tools: POC_RESEARCH_TOOLS,
	prompt: POC_RESEARCH_PROMPT,
};

export { POC_RESEARCH_MEMORY } from "./memory.ts";
export { POC_RESEARCH_MODEL } from "./model.ts";
export { POC_RESEARCH_PROMPT } from "./prompt.ts";
export { POC_RESEARCH_BUILT_IN_TOOL_CALLS, POC_RESEARCH_EXTERNAL_TOOL_CALLS, POC_RESEARCH_TOOLS } from "./tools.ts";
