import { ASSET_DISCOVERY_SUBAGENT } from "../asset-discovery/index.ts";
import { ATTACK_SURFACE_ANALYSIS_SUBAGENT } from "../attack-surface-analysis/index.ts";
import { POC_RESEARCH_SUBAGENT } from "../poc-research/index.ts";
import type { SecurityDedicatedSubagentDefinition, SecurityDedicatedSubagentName } from "../types.ts";

export const SECURITY_DEDICATED_SUBAGENTS: SecurityDedicatedSubagentDefinition[] = [
	ASSET_DISCOVERY_SUBAGENT,
	ATTACK_SURFACE_ANALYSIS_SUBAGENT,
	POC_RESEARCH_SUBAGENT,
];

export function getSecurityDedicatedSubagentDefinition(
	name: SecurityDedicatedSubagentName,
): SecurityDedicatedSubagentDefinition {
	const definition = SECURITY_DEDICATED_SUBAGENTS.find((subagent) => subagent.name === name);
	if (!definition) throw new Error(`Unknown security dedicated subagent: ${name}`);
	return definition;
}

export type {
	SecurityDedicatedSubagentDefinition,
	SecurityDedicatedSubagentExternalToolCall,
	SecurityDedicatedSubagentMemoryContract,
	SecurityDedicatedSubagentModel,
	SecurityDedicatedSubagentName,
	SecurityDedicatedSubagentPromptContract,
	SecurityDedicatedSubagentToolCall,
	SecurityDedicatedSubagentToolContract,
	SecurityDedicatedSubagentToolParameter,
} from "../types.ts";
