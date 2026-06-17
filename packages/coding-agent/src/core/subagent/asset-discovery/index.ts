import type { SecurityDedicatedSubagentDefinition } from "../types.ts";
import { ASSET_DISCOVERY_MEMORY } from "./memory.ts";
import { ASSET_DISCOVERY_MODEL } from "./model.ts";
import { ASSET_DISCOVERY_PROMPT } from "./prompt.ts";
import { ASSET_DISCOVERY_TOOLS } from "./tools.ts";

export const ASSET_DISCOVERY_SUBAGENT: SecurityDedicatedSubagentDefinition = {
	...ASSET_DISCOVERY_MODEL,
	model: ASSET_DISCOVERY_MODEL,
	memory: ASSET_DISCOVERY_MEMORY,
	tools: ASSET_DISCOVERY_TOOLS,
	prompt: ASSET_DISCOVERY_PROMPT,
};

export { ASSET_DISCOVERY_MEMORY } from "./memory.ts";
export { ASSET_DISCOVERY_MODEL } from "./model.ts";
export { ASSET_DISCOVERY_PROMPT } from "./prompt.ts";
export {
	ASSET_DISCOVERY_BUILT_IN_TOOL_CALLS,
	ASSET_DISCOVERY_EXTERNAL_TOOL_CALLS,
	ASSET_DISCOVERY_TOOLS,
} from "./tools.ts";
