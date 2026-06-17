import type { SecurityDedicatedSubagentDefinition } from "../types.ts";
import { ATTACK_SURFACE_ANALYSIS_MEMORY } from "./memory.ts";
import { ATTACK_SURFACE_ANALYSIS_MODEL } from "./model.ts";
import { ATTACK_SURFACE_ANALYSIS_PROMPT } from "./prompt.ts";
import { ATTACK_SURFACE_ANALYSIS_TOOLS } from "./tools.ts";

export const ATTACK_SURFACE_ANALYSIS_SUBAGENT: SecurityDedicatedSubagentDefinition = {
	...ATTACK_SURFACE_ANALYSIS_MODEL,
	model: ATTACK_SURFACE_ANALYSIS_MODEL,
	memory: ATTACK_SURFACE_ANALYSIS_MEMORY,
	tools: ATTACK_SURFACE_ANALYSIS_TOOLS,
	prompt: ATTACK_SURFACE_ANALYSIS_PROMPT,
};

export { ATTACK_SURFACE_ANALYSIS_MEMORY } from "./memory.ts";
export { ATTACK_SURFACE_ANALYSIS_MODEL } from "./model.ts";
export { ATTACK_SURFACE_ANALYSIS_PROMPT } from "./prompt.ts";
export {
	ATTACK_SURFACE_ANALYSIS_BUILT_IN_TOOL_CALLS,
	ATTACK_SURFACE_ANALYSIS_EXTERNAL_TOOL_CALLS,
	ATTACK_SURFACE_ANALYSIS_TOOLS,
} from "./tools.ts";
