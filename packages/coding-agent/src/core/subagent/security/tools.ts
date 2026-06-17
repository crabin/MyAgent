import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Type } from "typebox";
import { defineTool, type ToolDefinition } from "../../extensions/types.ts";
import { checkSecurityHeaders, checkTcpPorts, extractHostname } from "./active-scanning.ts";
import type { SecurityAuthorizationStore } from "./authorization.ts";
import { analyzeDetections } from "./detection-analysis.ts";
import { runSecurityExploration } from "./explore.ts";
import type { SecurityMemoryStore } from "./memory.ts";
import { discoverNetwork, expandDiscoveryTargets } from "./network-discovery.ts";
import { buildSecurityPayloadPrompt } from "./payload-model.ts";
import { assembleSecurityReport } from "./report.ts";
import { getSecurityMemoryPath } from "./session-memory.ts";
import type { SecurityTerminalManager } from "./terminal-session.ts";
import { assessVulnerabilities } from "./vulnerability-assessment.ts";
import { queryVulnerabilityDb } from "./vulnerability-db.ts";
import { apiClient, deepCrawl, type PageExtractResult, pageExtract, smartSearch } from "./web-research.ts";
import {
	buildSecurityStepExecutionPlan,
	buildSecuritySubagentDelegation,
	buildSecuritySubagentIterationPlan,
	buildSecurityWorkflowPlan,
} from "./workflow.ts";

export function createSecuritySubagentTools(
	authorization?: SecurityAuthorizationStore,
	terminal?: SecurityTerminalManager,
	memory?: SecurityMemoryStore,
): ToolDefinition[] {
	const approvalState: SecurityApprovalState = { approveAllNextPhaseRequests: false };
	return [
		createSecurityAuthorizeTool(authorization),
		createSecurityUserApprovalTool(approvalState),
		createSecurityScopeStatusTool(authorization),
		createSecurityMemoryTool(memory),
		securityWorkflowPlanTool,
		securityDelegateSubagentTool,
		securitySubagentIterationPlanTool,
		securityStepExecutionPlanTool,
		createSecurityResearchTool(authorization),
		createSecurityWebAnalysisTool(authorization),
		createSecurityExploreTool(authorization),
		smartSearchTool,
		pageExtractTool,
		createSecurityCrawlTool(authorization),
		deepCrawlTool,
		apiClientTool,
		vulnDbQueryTool,
		createSecurityPortCheckTool(authorization),
		createSecurityNetworkDiscoveryTool(authorization),
		createSecurityHeaderCheckTool(authorization),
		createSecurityExternalToolRunnerTool(authorization, terminal),
		createSecurityTerminalSessionTool(authorization, terminal),
		createSecurityPayloadModelPromptTool(authorization),
		securityDetectionAnalysisTool,
		securityAssessmentTool,
		securityVulnerabilityAssessmentTool,
		createSecurityReportTool(memory),
	];
}

interface SecurityApprovalState {
	approveAllNextPhaseRequests: boolean;
}

const MANUAL_SUGGESTION_OPTION = "人工建议";

const createSecurityUserApprovalTool = (state: SecurityApprovalState) =>
	defineTool({
		name: "security_user_approval",
		label: "Security User Approval",
		description:
			"Requests an interactive Codex-style user approval with selectable choices. Uses Enter to accept the highlighted choice, Up/Down to change selection, and the manual-suggestion option to collect typed guidance.",
		promptSnippet:
			"Ask the user for interactive approval before security authorization, scope expansion, phase transitions, or higher-risk actions.",
		promptGuidelines: [
			"Use security_user_approval for every penetration-testing phase transition, initial authorization confirmation, scope expansion, full-port discovery, exploitation, privilege escalation, and reviewed command/payload execution.",
			"Do not replace this with a free-text question when dialog-capable UI is available.",
			"For next-phase approvals, offer an approve-all-next-phases option; it must not apply to scope expansion, full-port discovery, exploitation, privilege escalation, or command/payload execution.",
			"Every selector should include 人工建议; when selected, collect the operator's typed guidance and feed it into replanning or generation instead of treating it as approval.",
			"If the result is not approved, stop the gated action and ask what the user wants to change.",
		],
		parameters: Type.Object({
			title: Type.String({ description: "Short approval title shown in the selector" }),
			message: Type.String({ description: "Concise approval details, including target, action, scope, and risk" }),
			request_type: Type.Optional(
				Type.Union([
					Type.Literal("authorization_scope"),
					Type.Literal("phase_start"),
					Type.Literal("scope_expansion"),
					Type.Literal("dangerous_action"),
				]),
			),
			approve_label: Type.Optional(Type.String({ description: "Approve option label. Defaults to Approve." })),
			approve_all_next_phases_label: Type.Optional(
				Type.String({
					description:
						"Approve-all option label for request_type=phase_start. Defaults to approving all next-phase requests in this session.",
				}),
			),
			reject_label: Type.Optional(Type.String({ description: "Reject option label. Defaults to Reject." })),
			options: Type.Optional(
				Type.Array(Type.String(), {
					description:
						"Full selector options to display. Use this for operatorChoicePrompt/options; 人工建议 is appended if missing.",
				}),
			),
			default_option: Type.Optional(Type.String({ description: "Default or recommended option label." })),
			manual_suggestion_label: Type.Optional(
				Type.String({ description: "Manual suggestion option label. Defaults to 人工建议." }),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const requestType = params.request_type ?? "phase_start";
			const approveLabel = params.approve_label?.trim() || "Approve";
			const approveAllLabel =
				params.approve_all_next_phases_label?.trim() || "Approve all next-phase requests this session";
			const rejectLabel = params.reject_label?.trim() || "Reject";
			const manualSuggestionLabel = params.manual_suggestion_label?.trim() || MANUAL_SUGGESTION_OPTION;
			const options = buildApprovalOptions({
				requestType,
				approveLabel,
				approveAllLabel,
				rejectLabel,
				manualSuggestionLabel,
				customOptions: params.options,
			});
			if (requestType === "phase_start" && state.approveAllNextPhaseRequests) {
				return toolResult("Next-phase request auto-approved for this session.", {
					approved: true,
					choice: approveAllLabel,
					ui: "remembered",
					rememberedApproval: "next_phase_requests",
					message: params.message,
				});
			}
			if (!ctx.hasUI) {
				return toolResult("Interactive approval UI is unavailable. Approval was not granted.", {
					approved: false,
					choice: null,
					ui: "unavailable",
					requiredTextConfirmation: `${approveLabel}: ${params.title}`,
					options,
				});
			}
			const choice = await ctx.ui.select(renderApprovalTitle(params.title, params.message), options, {
				signal: ctx.signal,
			});
			if (choice === manualSuggestionLabel) {
				const manualSuggestion = await ctx.ui.input(
					`${params.title} - ${manualSuggestionLabel}`,
					"Type guidance for replanning or generation",
					{ signal: ctx.signal },
				);
				return toolResult("User provided manual guidance for replanning.", {
					approved: false,
					choice,
					ui: "manual_input",
					message: params.message,
					manualSuggestion: manualSuggestion?.trim() || "",
					replanRequired: true,
					keyboard: {
						confirm: "Enter",
						navigate: "Up/Down",
						manualInput: "Tab",
					},
				});
			}
			const approved = choice === approveLabel || choice === approveAllLabel;
			if (choice === approveAllLabel) {
				state.approveAllNextPhaseRequests = true;
			}
			return toolResult(approved ? "User approved the security action." : "User rejected the security action.", {
				approved,
				choice: choice ?? null,
				ui: "select",
				message: params.message,
				rememberedApproval: choice === approveAllLabel ? "next_phase_requests" : null,
				keyboard: {
					confirm: "Enter",
					navigate: "Up/Down",
					manualInput: "Tab",
				},
			});
		},
	});

function buildApprovalOptions(input: {
	requestType: "authorization_scope" | "phase_start" | "scope_expansion" | "dangerous_action";
	approveLabel: string;
	approveAllLabel: string;
	rejectLabel: string;
	manualSuggestionLabel: string;
	customOptions?: string[];
}): string[] {
	const baseOptions =
		input.customOptions && input.customOptions.length > 0
			? input.customOptions.map((option) => option.trim()).filter((option) => option.length > 0)
			: input.requestType === "phase_start"
				? [input.approveLabel, input.approveAllLabel, input.rejectLabel]
				: [input.approveLabel, input.rejectLabel];
	return baseOptions.includes(input.manualSuggestionLabel)
		? baseOptions
		: [...baseOptions, input.manualSuggestionLabel];
}

function renderApprovalTitle(title: string, message: string): string {
	const trimmedMessage = message.trim();
	return trimmedMessage ? `${title}\n\n${trimmedMessage}` : title;
}

const createSecurityAuthorizeTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_authorize_scope",
		label: "Authorize Security Scope",
		description:
			"Records an explicit user-approved defensive security scope for this session. Does not run scans or network actions.",
		promptSnippet: "Record the user's explicit authorization scope for defensive security work.",
		promptGuidelines: [
			"Use security_authorize_scope only after the user explicitly states the authorized targets and permitted defensive purpose.",
			"Do not treat this tool as permission to act outside the approved targets, action categories, or duration.",
		],
		parameters: Type.Object({
			targets: Type.Array(Type.String(), { description: "Authorized hosts, domains, URLs, or assets" }),
			allowed_actions: Type.Optional(
				Type.Array(Type.String(), { description: "Allowed defensive action categories" }),
			),
			reason: Type.Optional(Type.String({ description: "User-stated authorization reason or ticket reference" })),
			expires_at: Type.Optional(Type.String({ description: "ISO timestamp when this authorization expires" })),
		}),
		async execute(_toolCallId, params) {
			if (!authorization) {
				throw new Error("Security authorization store is unavailable.");
			}
			const result = authorization.authorize({
				targets: params.targets,
				allowedActions: params.allowed_actions,
				reason: params.reason,
				expiresAt: params.expires_at,
			});
			return toolResult("Security scope recorded. No scan was run.", result);
		},
	});

const createSecurityScopeStatusTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_scope_status",
		label: "Security Scope Status",
		description: "Shows the current in-session defensive security authorization scope.",
		promptSnippet: "Check whether an explicit security authorization scope is active.",
		promptGuidelines: [
			"Use security_scope_status before active security work to verify the current target and action scope.",
		],
		parameters: Type.Object({}),
		async execute() {
			if (!authorization) {
				throw new Error("Security authorization store is unavailable.");
			}
			const result = authorization.status();
			return toolResult(result.authorized ? "Security scope is active." : "No active security scope.", result);
		},
	});

const createSecurityMemoryTool = (memory: SecurityMemoryStore | undefined) =>
	defineTool({
		name: "security_memory",
		label: "Security Memory",
		description:
			"Security memory for short-term notes, episodic lessons, long-term facts, semantic recall, context assembly, and session-local persistence.",
		promptSnippet: "Store and recall security assessment context, lessons, and reusable knowledge for this session.",
		promptGuidelines: [
			"Use security_memory to remember scoped findings, assumptions, authorization facts, and useful defensive knowledge.",
			"Do not store secrets, credentials, payloads for exploitation, or sensitive personal data.",
			"Use action=context before complex follow-up work to assemble relevant security memory under a token budget.",
		],
		parameters: Type.Object({
			action: Type.Union([
				Type.Literal("remember"),
				Type.Literal("recall"),
				Type.Literal("context"),
				Type.Literal("stats"),
				Type.Literal("persist"),
				Type.Literal("load"),
				Type.Literal("clear"),
			]),
			content: Type.Optional(Type.String({ description: "Memory content for action=remember" })),
			memory_type: Type.Optional(
				Type.Union([Type.Literal("short_term"), Type.Literal("episodic"), Type.Literal("long_term")]),
			),
			query: Type.Optional(Type.String({ description: "Recall/context query" })),
			importance: Type.Optional(Type.Number({ description: "Importance from 0 to 1. Default 0.5." })),
			metadata: Type.Optional(Type.Record(Type.String(), Type.Unknown(), { description: "Structured metadata" })),
			limit: Type.Optional(Type.Number({ description: "Recall limit, 1-50. Default 8." })),
			budget_tokens: Type.Optional(Type.Number({ description: "Context budget estimate, 100-8000. Default 1200." })),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			if (!memory) {
				throw new Error("Security memory store is unavailable.");
			}
			if (params.action === "remember") {
				if (!params.content) {
					throw new Error("content is required for action=remember.");
				}
				const result = memory.remember({
					content: params.content,
					type: params.memory_type,
					importance: params.importance,
					metadata: params.metadata,
				});
				return toolResult("Security memory stored", result);
			}
			if (params.action === "recall") {
				const result = memory.recall({
					query: params.query,
					type: params.memory_type,
					limit: params.limit,
				});
				return toolResult(`Recalled ${result.length} security memor${result.length === 1 ? "y" : "ies"}`, result);
			}
			if (params.action === "context") {
				const result = memory.context({ query: params.query, budgetTokens: params.budget_tokens });
				return toolResult("Security memory context assembled", result);
			}
			if (params.action === "persist") {
				const result = memory.saveToFile(getSecurityMemoryPath(ctx));
				return toolResult("Security memory persisted", result);
			}
			if (params.action === "load") {
				const result = memory.loadFromFile(getSecurityMemoryPath(ctx));
				return toolResult("Security memory loaded", result);
			}
			if (params.action === "clear") {
				memory.clear(params.memory_type);
				return toolResult("Security memory cleared", memory.stats());
			}
			return toolResult("Security memory stats", memory.stats());
		},
	});

const securityWorkflowPlanTool = defineTool({
	name: "security_workflow_plan",
	label: "Security Workflow Plan",
	description:
		"Creates a safe ReAct, Plan-Execute, or multi-agent coordination plan for a defensive security request without executing scans.",
	promptSnippet: "Plan the security subagent workflow, roles, authorization gate, tools, and report path.",
	promptGuidelines: [
		"Use security_workflow_plan before complex security tasks or when deciding between ReAct, plan-execute, and multi-agent coordination.",
		"Treat the plan as guidance only; active validation still requires explicit scope authorization.",
		"Do not include exploitation, persistence, credential access, privilege escalation, lateral movement, reverse shells, or remote control steps.",
	],
	parameters: Type.Object({
		objective: Type.String({ description: "The user's defensive security objective" }),
		targets: Type.Optional(Type.Array(Type.String(), { description: "Known targets, hosts, URLs, or assets" })),
		authorization_confirmed: Type.Optional(
			Type.Boolean({ description: "Whether explicit user authorization is already recorded" }),
		),
		include_exploration: Type.Optional(
			Type.Boolean({ description: "Include read-only exploration phase. Defaults from intent." }),
		),
		include_active_validation: Type.Optional(
			Type.Boolean({ description: "Include authorization-gated active validation. Defaults from intent." }),
		),
		include_report: Type.Optional(
			Type.Boolean({ description: "Include report-writing phase. Defaults from intent." }),
		),
		complexity: Type.Optional(Type.Union([Type.Literal("simple"), Type.Literal("complex")])),
	}),
	async execute(_toolCallId, params) {
		const result = buildSecurityWorkflowPlan({
			objective: params.objective,
			targets: params.targets,
			authorizationConfirmed: params.authorization_confirmed,
			includeExploration: params.include_exploration,
			includeActiveValidation: params.include_active_validation,
			includeReport: params.include_report,
			complexity: params.complexity,
		});
		return toolResult(`Security workflow planned in ${result.mode} mode`, result);
	},
});

const securityDelegateSubagentTool = defineTool({
	name: "security_delegate_subagent",
	label: "Security Delegate Subagent",
	description:
		"Invokes the phase-specific dedicated security subagent contract and returns its prompt, memory, tool plan, external methods, safety checks, and handoff requirements.",
	promptSnippet:
		"Call this at the start of asset discovery, attack surface analysis, or PoC research to enter the matching dedicated subagent.",
	promptGuidelines: [
		"Call security_delegate_subagent immediately after security_step_execution_plan when selectedToolCalls includes it.",
		"Use the returned systemPrompt, requiredTools, optionalTools, toolCalls, externalToolCalls, and handoffRequirements as the phase-local execution contract.",
		"Do not run another phase's responsibilities inside the delegated subagent.",
		"Do not treat delegation as authorization for active validation; security_scope_status and user approval still gate active work.",
	],
	parameters: Type.Object({
		subagent: Type.Union([
			Type.Literal("asset_discovery"),
			Type.Literal("attack_surface_analysis"),
			Type.Literal("poc_research"),
		]),
		phase: Type.Union([
			Type.Literal("asset_discovery"),
			Type.Literal("attack_surface_analysis"),
			Type.Literal("vulnerability_scanning"),
		]),
		objective: Type.String({ description: "The current phase objective" }),
		targets: Type.Optional(Type.Array(Type.String(), { description: "Known authorized targets for this phase" })),
		prior_results: Type.Optional(
			Type.Array(Type.String({ description: "Summaries of previous phase outputs and limitations" })),
		),
		missing_information: Type.Optional(
			Type.Array(Type.String({ description: "Known gaps this dedicated subagent must collect" })),
		),
	}),
	async execute(_toolCallId, params) {
		const result = buildSecuritySubagentDelegation({
			subagent: params.subagent,
			phase: params.phase,
			objective: params.objective,
			targets: params.targets,
			priorResults: params.prior_results,
			missingInformation: params.missing_information,
		});
		return toolResult(`${result.displayName} delegated for ${result.phase}`, result);
	},
});

const securitySubagentIterationPlanTool = defineTool({
	name: "security_subagent_iteration_plan",
	label: "Security Subagent Iteration Plan",
	description:
		"Plans or replans one dedicated subagent iteration from prior results, new evidence, missing information, and tool errors. Returns continue, complete, or manual_intervention.",
	promptSnippet:
		"Call this before the first dedicated subagent tool round and after each round to decide whether to continue, complete, or request manual input.",
	promptGuidelines: [
		"Call security_subagent_iteration_plan at the start of asset discovery, attack surface analysis, and PoC research after security_delegate_subagent.",
		"Call it again after each tool round with collected_evidence, missing_information, and tool_errors.",
		"Continue only when it returns decision=continue; stop the subagent phase only when decision=complete or manual_intervention.",
		"Before complete or manual_intervention, use the returned memoryActions to persist evidence, limitations, errors, and handoff state.",
	],
	parameters: Type.Object({
		subagent: Type.Union([
			Type.Literal("asset_discovery"),
			Type.Literal("attack_surface_analysis"),
			Type.Literal("poc_research"),
		]),
		phase: Type.Union([
			Type.Literal("asset_discovery"),
			Type.Literal("attack_surface_analysis"),
			Type.Literal("vulnerability_scanning"),
		]),
		objective: Type.String({ description: "The current dedicated subagent objective" }),
		targets: Type.Optional(Type.Array(Type.String(), { description: "Known authorized targets for this phase" })),
		iteration: Type.Optional(Type.Number({ description: "Current subagent iteration number, starting at 1" })),
		prior_results: Type.Optional(
			Type.Array(Type.String({ description: "Evidence and handoff outputs from earlier phases" })),
		),
		collected_evidence: Type.Optional(
			Type.Array(Type.String({ description: "Evidence collected by this subagent so far" })),
		),
		missing_information: Type.Optional(
			Type.Array(Type.String({ description: "Unresolved criteria, gaps, or low-confidence outputs" })),
		),
		tool_errors: Type.Optional(
			Type.Array(Type.String({ description: "Tool call errors, blocked external methods, or parsing failures" })),
		),
		completed_objectives: Type.Optional(
			Type.Array(Type.String({ description: "Completion criteria already satisfied by the current subagent" })),
		),
		max_iterations: Type.Optional(
			Type.Number({ description: "Maximum replanning rounds before manual intervention" }),
		),
	}),
	async execute(_toolCallId, params) {
		const result = buildSecuritySubagentIterationPlan({
			subagent: params.subagent,
			phase: params.phase,
			objective: params.objective,
			targets: params.targets,
			iteration: params.iteration,
			priorResults: params.prior_results,
			collectedEvidence: params.collected_evidence,
			missingInformation: params.missing_information,
			toolErrors: params.tool_errors,
			completedObjectives: params.completed_objectives,
			maxIterations: params.max_iterations,
		});
		return toolResult(`${result.displayName} iteration ${result.iteration}: ${result.decision}`, result);
	},
});

const securityStepExecutionPlanTool = defineTool({
	name: "security_step_execution_plan",
	label: "Security Step Execution Plan",
	description:
		"Builds the phase-specific prompt and selected tool call plan for one penetration-testing workflow step based on prior results and missing information.",
	promptSnippet:
		"Before each penetration-testing phase, generate the concrete step prompt and selected tool calls from prior evidence.",
	promptGuidelines: [
		"Call security_step_execution_plan before each penetration-testing phase.",
		"After receiving the plan, call each required selected tool unless authorization is missing.",
		"Use prior_results and missing_information so later phases are decided from collected evidence, not a static checklist.",
	],
	parameters: Type.Object({
		phase: Type.Union([
			Type.Literal("clarify"),
			Type.Literal("asset_discovery"),
			Type.Literal("attack_surface_analysis"),
			Type.Literal("vulnerability_scanning"),
			Type.Literal("manual_validation"),
			Type.Literal("exploitation"),
			Type.Literal("privilege_escalation"),
			Type.Literal("attack_chain"),
			Type.Literal("risk_assessment"),
			Type.Literal("remediation"),
			Type.Literal("retest"),
			Type.Literal("closeout"),
		]),
		objective: Type.String({ description: "The current defensive security objective" }),
		targets: Type.Optional(Type.Array(Type.String(), { description: "Known authorized targets for this phase" })),
		authorization_confirmed: Type.Optional(
			Type.Boolean({ description: "Whether active authorization has been confirmed for this phase" }),
		),
		prior_results: Type.Optional(
			Type.Array(
				Type.String({
					description:
						"Summaries of outputs from completed prior tools or phases, such as open ports, URLs, findings, report paths, or limitations",
				}),
			),
		),
		missing_information: Type.Optional(
			Type.Array(Type.String({ description: "Known gaps this phase must collect before moving on" })),
		),
	}),
	async execute(_toolCallId, params) {
		const result = buildSecurityStepExecutionPlan({
			phase: params.phase,
			objective: params.objective,
			targets: params.targets,
			authorizationConfirmed: params.authorization_confirmed,
			priorResults: params.prior_results,
			missingInformation: params.missing_information,
		});
		return toolResult(
			`Security ${result.phase} execution plan selected ${result.selectedToolCalls.length} tool(s)`,
			result,
		);
	},
});

const createSecurityExplorationTool = (
	authorization: SecurityAuthorizationStore | undefined,
	input: {
		name: "security_explore" | "security_research";
		label: string;
		description: string;
		promptSnippet: string;
		promptGuidelines: string[];
		resultPrefix: string;
	},
) =>
	defineTool({
		name: input.name,
		label: input.label,
		description: input.description,
		promptSnippet: input.promptSnippet,
		promptGuidelines: input.promptGuidelines,
		parameters: Type.Object({
			query: Type.String({ description: "Security research question, product/version, CVE, or target context" }),
			target_url: Type.Optional(Type.String({ description: "Optional HTTP/HTTPS target URL for page extraction" })),
			cve_id: Type.Optional(Type.String({ description: "Optional CVE ID such as CVE-2021-44228" })),
			vulnerability_source: Type.Optional(
				Type.Union([
					Type.Literal("cve"),
					Type.Literal("nvd"),
					Type.Literal("exploit_db"),
					Type.Literal("mitre_attack"),
					Type.Literal("all"),
				]),
			),
			max_results: Type.Optional(
				Type.Number({ description: "Maximum search/vulnerability results, 1-10. Default 5." }),
			),
			crawl_depth: Type.Optional(
				Type.Number({ description: "Optional crawl depth, 0-3. Used only when include_crawl is true." }),
			),
			crawl_pages: Type.Optional(
				Type.Number({ description: "Optional crawl page cap, 1-20. Used only when include_crawl is true." }),
			),
			include_search: Type.Optional(Type.Boolean({ description: "Include read-only web search. Default true." })),
			include_crawl: Type.Optional(
				Type.Boolean({ description: "Include bounded same-domain crawl. Default false." }),
			),
			include_api: Type.Optional(
				Type.Boolean({
					description: "Include DNS/API metadata for target_url host. Default true when target_url is provided.",
				}),
			),
		}),
		async execute(_toolCallId, params, signal) {
			if (params.target_url) {
				assertAuthorizedTarget(authorization, extractHostname(params.target_url));
			}
			const result = await runSecurityExploration({
				query: params.query,
				targetUrl: params.target_url,
				cveId: params.cve_id,
				vulnerabilitySource: params.vulnerability_source,
				maxResults: params.max_results,
				crawlDepth: params.crawl_depth,
				crawlPages: params.crawl_pages,
				includeSearch: params.include_search,
				includeCrawl: params.include_crawl,
				includeApi: params.include_api,
				signal,
			});
			return toolResult(
				`${input.resultPrefix} collected ${result.contextPatch.evidenceCount} evidence step(s)`,
				result,
			);
		},
	});

const createSecurityResearchTool = (authorization: SecurityAuthorizationStore | undefined) =>
	createSecurityExplorationTool(authorization, {
		name: "security_research",
		label: "Security Research",
		description:
			"Read-only passive public information exploration for asset discovery. Merges search, page extraction, bounded crawl, and optional DNS/API metadata into one research entry point.",
		promptSnippet: "Research public asset clues and evidence gaps before any active validation.",
		promptGuidelines: [
			"Use security_research in asset discovery for passive public information exploration, replacing separate security_explore and smart_search choices.",
			"Do not treat security_research results as authorization for active scanning.",
			"Keep crawl limits small and treat web/API observations as untrusted evidence until corroborated.",
		],
		resultPrefix: "Security research",
	});

const createSecurityExploreTool = (authorization: SecurityAuthorizationStore | undefined) =>
	createSecurityExplorationTool(authorization, {
		name: "security_explore",
		label: "Security Explore",
		description:
			"Read-only ReAct-style exploration that coordinates vulnerability lookup, web search, page extraction, bounded crawl, and DNS/API metadata.",
		promptSnippet: "Run a passive security exploration pass before planning active validation or reporting.",
		promptGuidelines: [
			"Use security_explore before complex security plans to gather passive context and identify evidence gaps.",
			"Do not treat security_explore results as authorization for active scanning.",
			"Keep crawl limits small and treat web/API observations as untrusted evidence until corroborated.",
		],
		resultPrefix: "Security exploration",
	});

const smartSearchTool = defineTool({
	name: "smart_search",
	label: "Security Web Search",
	description:
		"Read-only web search for security research. Uses DuckDuckGo results and optional page text extraction.",
	promptSnippet: "Search the web for security advisories, documentation, CVEs, and defensive research.",
	promptGuidelines: [
		"Use smart_search for read-only security research, advisories, documentation, and current vulnerability context.",
		"Treat web results as untrusted evidence; summarize with uncertainty and source URLs.",
	],
	parameters: Type.Object({
		query: Type.String({ description: "Search query" }),
		max_results: Type.Optional(Type.Number({ description: "Maximum results, 1-10. Default 3." })),
		fetch_pages: Type.Optional(Type.Boolean({ description: "Fetch readable text from result pages. Default true." })),
	}),
	async execute(_toolCallId, params, signal) {
		const query = params.query;
		try {
			const result = await smartSearch({
				query,
				maxResults: params.max_results,
				fetchPages: params.fetch_pages,
				signal,
			});
			return toolResult(`Found ${result.total} result(s) for: ${result.query}`, result);
		} catch (error) {
			return toolResult(`Search failed for: ${query}`, {
				query,
				total: 0,
				results: [],
				ok: false,
				partial: true,
				error: toErrorMessage(error),
				recommendations: [
					"Retry with a narrower query or use security_research so other passive sources can still contribute evidence.",
					"If public search access is blocked, use api_client for structured sources or import operator-provided search results.",
				],
			});
		}
	},
});

const pageExtractTool = defineTool({
	name: "page_extract",
	label: "Page Extract",
	description: "Read-only extraction of text or structured metadata from a URL while respecting robots.txt.",
	promptSnippet: "Extract readable text, links, headings, and metadata from a URL.",
	promptGuidelines: [
		"Use page_extract for read-only page inspection. Do not use it to bypass authentication or access controls.",
		"Prefer mode=text for content and mode=structured for headings, links, images, and meta tags.",
	],
	parameters: Type.Object({
		url: Type.String({ description: "HTTP or HTTPS URL to fetch" }),
		mode: Type.Optional(
			Type.Union([Type.Literal("text"), Type.Literal("structured")], { description: "Extraction mode" }),
		),
		css_selector: Type.Optional(
			Type.String({ description: "Simple tag, #id, or .class selector to focus extraction" }),
		),
		timeout_ms: Type.Optional(Type.Number({ description: "Fetch timeout in milliseconds" })),
	}),
	async execute(_toolCallId, params, signal) {
		try {
			const result = await pageExtract({
				url: params.url,
				mode: params.mode,
				cssSelector: params.css_selector,
				timeoutMs: params.timeout_ms,
				signal,
			});
			return toolResult(`Extracted ${result.mode} content from ${result.url}`, result);
		} catch (error) {
			return toolResult(`Page extraction failed for ${params.url}`, {
				url: params.url,
				mode: params.mode ?? "text",
				ok: false,
				partial: true,
				error: toErrorMessage(error),
				recommendations: [
					"Use api_client for robots.txt, sitemap.xml, OpenAPI, GraphQL, and non-HTML metadata endpoints.",
					"Check whether the endpoint requires a different scheme, redirects to authentication, blocks the user agent, or serves a non-HTML content type.",
				],
			});
		}
	},
});

const createSecurityWebAnalysisTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_web_analysis",
		label: "Security Web Analysis",
		description:
			"Authorization-gated read-only web page analysis that combines HTTP security headers with structured page metadata.",
		promptSnippet:
			"Analyze an authorized web endpoint once for title, headers, forms, links, scripts, metadata, technologies, and auth indicators.",
		promptGuidelines: [
			"Use security_web_analysis in attack surface analysis instead of choosing separately between security_header_check and page_extract.",
			"Use only for authorized HTTP or HTTPS targets and treat observations as evidence requiring corroboration.",
			"Do not bypass authentication, submit forms, execute payloads, or collect private authenticated content.",
		],
		parameters: Type.Object({
			url: Type.String({ description: "Authorized HTTP or HTTPS URL" }),
			timeout_ms: Type.Optional(Type.Number({ description: "Page fetch timeout in milliseconds" })),
			include_page: Type.Optional(Type.Boolean({ description: "Fetch structured page metadata. Default true." })),
		}),
		async execute(_toolCallId, params, signal) {
			const host = extractHostname(params.url);
			assertAuthorizedTarget(authorization, host);
			const headerResult = await Promise.resolve(checkSecurityHeaders(params.url, signal)).then(
				(value) => ({ ok: true as const, value }),
				(error: unknown) => ({ ok: false as const, error: toErrorMessage(error) }),
			);
			const pageResult =
				params.include_page === false
					? ({ ok: true as const, value: null } as const)
					: await Promise.resolve(
							pageExtract({
								url: params.url,
								mode: "structured",
								timeoutMs: params.timeout_ms,
								signal,
							}),
						).then(
							(value) => ({ ok: true as const, value }),
							(error: unknown) => ({ ok: false as const, error: toErrorMessage(error) }),
						);
			const headerAnalysis = headerResult.ok ? headerResult.value : null;
			const pageAnalysis = pageResult.ok ? pageResult.value : null;
			const errors = [
				headerResult.ok ? null : { stage: "headers", message: headerResult.error },
				pageResult.ok ? null : { stage: "page_extract", message: pageResult.error },
			].filter((error) => error !== null);
			return toolResult(
				errors.length === 0
					? `Analyzed web surface for ${params.url}`
					: `Web analysis partially completed for ${params.url}`,
				{
					url: headerAnalysis?.url ?? pageAnalysis?.url ?? params.url,
					title: pageAnalysis?.title ?? "",
					headers: headerAnalysis,
					forms: [],
					links: pageAnalysis?.links ?? [],
					scripts: [],
					meta: pageAnalysis?.meta ?? {},
					technologies: [],
					authIndicators: inferAuthIndicators(pageAnalysis),
					page: pageAnalysis,
					partial: errors.length > 0,
					errors,
					recommendations:
						errors.length > 0
							? [
									"Check whether the service requires HTTP instead of HTTPS, uses a self-signed/untrusted certificate, rejects HEAD requests, or returns non-HTML metadata such as robots.txt/sitemap.xml.",
									"Use api_client for robots.txt, sitemap.xml, OpenAPI, GraphQL, DNS, and IP metadata because page extraction accepts HTML pages only.",
									"Use security_external_tool_runner with approved read-only tools such as httpx, curl, openssl s_client, or whatweb when Node fetch cannot inspect the service.",
								]
							: [],
				},
			);
		},
	});

const deepCrawlTool = defineTool({
	name: "deep_crawl",
	label: "Deep Crawl",
	description: "Read-only breadth-first crawl with depth/page/domain limits while respecting robots.txt.",
	promptSnippet: "Crawl a small, bounded set of pages for defensive security research.",
	promptGuidelines: [
		"Use deep_crawl only for small, bounded, read-only crawls.",
		"Keep max_pages and max_depth low unless the user explicitly authorizes broader collection.",
	],
	parameters: Type.Object({
		start_url: Type.String({ description: "HTTP or HTTPS URL to start crawling from" }),
		max_depth: Type.Optional(Type.Number({ description: "Maximum crawl depth, 0-3. Default 1." })),
		max_pages: Type.Optional(Type.Number({ description: "Maximum pages, 1-20. Default 5." })),
		same_domain: Type.Optional(Type.Boolean({ description: "Restrict crawl to the start domain. Default true." })),
		url_pattern: Type.Optional(Type.String({ description: "Optional regular expression URLs must match" })),
	}),
	async execute(_toolCallId, params, signal) {
		try {
			const result = await deepCrawl({
				startUrl: params.start_url,
				maxDepth: params.max_depth,
				maxPages: params.max_pages,
				sameDomain: params.same_domain,
				urlPattern: params.url_pattern,
				signal,
			});
			return toolResult(`Crawled ${result.pagesCrawled} page(s) from ${result.startUrl}`, result);
		} catch (error) {
			return toolResult(`Crawl failed for ${params.start_url}`, {
				startUrl: params.start_url,
				maxDepth: params.max_depth ?? 1,
				pagesCrawled: 0,
				pages: [],
				errors: [{ url: params.start_url, depth: 0, message: toErrorMessage(error) }],
				partial: true,
			});
		}
	},
});

const createSecurityCrawlTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_crawl",
		label: "Security Crawl",
		description: "Authorization-gated route, API, and JavaScript link discovery through a bounded read-only crawl.",
		promptSnippet: "Discover routes, API hints, and JavaScript-linked URLs with bounded crawl parameters.",
		promptGuidelines: [
			"Use security_crawl in attack surface analysis for route discovery, API discovery, and JavaScript link discovery.",
			"Tune max_depth, max_pages, same_domain, and url_pattern instead of choosing separate small/deep crawl tools.",
			"Do not crawl outside authorization scope, bypass authentication, scrape sensitive data, or stress the target.",
		],
		parameters: Type.Object({
			start_url: Type.String({ description: "Authorized HTTP or HTTPS URL to start crawling from" }),
			max_depth: Type.Optional(Type.Number({ description: "Maximum crawl depth, 0-3. Default 1." })),
			max_pages: Type.Optional(Type.Number({ description: "Maximum pages, 1-20. Default 5." })),
			same_domain: Type.Optional(Type.Boolean({ description: "Restrict crawl to the start domain. Default true." })),
			url_pattern: Type.Optional(Type.String({ description: "Optional regular expression URLs must match" })),
		}),
		async execute(_toolCallId, params, signal) {
			assertAuthorizedTarget(authorization, extractHostname(params.start_url));
			const result = await deepCrawl({
				startUrl: params.start_url,
				maxDepth: params.max_depth,
				maxPages: params.max_pages,
				sameDomain: params.same_domain,
				urlPattern: params.url_pattern,
				signal,
			});
			return toolResult(`Discovered ${result.pagesCrawled} crawl page(s) from ${result.startUrl}`, result);
		},
	});

const apiClientTool = defineTool({
	name: "api_client",
	label: "API Client",
	description:
		"Generic read-oriented REST client with security research presets and structured vulnerability metadata lookup.",
	promptSnippet: "Call safe REST APIs, DNS/IP/GitHub presets, or structured vulnerability metadata sources.",
	promptGuidelines: [
		"Use api_client for read-oriented API calls, metadata lookups, and structured vulnerability sources such as CVE.org, NVD, MITRE ATT&CK, and Exploit-DB metadata.",
		"Do not send credentials, exploit payloads, or destructive methods unless the user has clearly authorized a safe target and purpose.",
	],
	parameters: Type.Object({
		preset: Type.Optional(
			Type.String({ description: "Preset: dns_resolve, ip_info, ip_self, github_repo, github_user" }),
		),
		query: Type.Optional(Type.String({ description: "Preset query value" })),
		url: Type.Optional(Type.String({ description: "Custom HTTP/HTTPS URL" })),
		method: Type.Optional(Type.String({ description: "HTTP method. Default GET." })),
		headers: Type.Optional(Type.Record(Type.String(), Type.String(), { description: "Request headers" })),
		params: Type.Optional(Type.Record(Type.String(), Type.String(), { description: "Query parameters" })),
		body: Type.Optional(Type.Unknown({ description: "JSON or text body for non-GET requests" })),
		timeout_sec: Type.Optional(Type.Number({ description: "Timeout in seconds, 1-60. Default 20." })),
		source: Type.Optional(
			Type.Union([
				Type.Literal("cve"),
				Type.Literal("nvd"),
				Type.Literal("exploit_db"),
				Type.Literal("mitre_attack"),
				Type.Literal("all"),
			]),
		),
		cve_id: Type.Optional(Type.String({ description: "CVE ID such as CVE-2021-44228 for structured lookup" })),
		limit: Type.Optional(Type.Number({ description: "Maximum structured vulnerability matches, 1-20. Default 10." })),
	}),
	async execute(_toolCallId, params, signal) {
		if (params.source || params.cve_id) {
			const result = await Promise.resolve(
				queryVulnerabilityDb({
					source: params.source,
					cveId: params.cve_id,
					query: params.query,
					limit: params.limit,
					signal,
				}),
			).then(
				(value) => ({ ok: true as const, value }),
				(error: unknown) => ({ ok: false as const, error: toErrorMessage(error) }),
			);
			if (!result.ok) {
				return toolResult("Structured vulnerability metadata lookup failed", {
					ok: false,
					partial: true,
					error: result.error,
					source: params.source ?? null,
					cveId: params.cve_id ?? null,
					query: params.query ?? null,
					recommendations: [
						"Continue with security_research or external source groups when a structured vulnerability API is unavailable.",
						"Record this source as unavailable in security_memory and include the limitation in security_report.",
					],
				});
			}
			return toolResult("Structured vulnerability metadata lookup completed", result.value);
		}
		const result = await Promise.resolve(
			apiClient({
				preset: params.preset,
				query: params.query,
				url: params.url,
				method: params.method,
				headers: params.headers,
				params: params.params,
				body: params.body,
				timeoutSec: params.timeout_sec,
				signal,
			}),
		).then(
			(value) => ({ ok: true as const, value }),
			(error: unknown) => ({ ok: false as const, error: toErrorMessage(error) }),
		);
		if (!result.ok) {
			return toolResult("API request failed", {
				ok: false,
				partial: true,
				error: result.error,
				preset: params.preset ?? null,
				query: params.query ?? null,
				url: params.url ?? null,
				method: params.method ?? "GET",
				recommendations: [
					"Check whether the endpoint requires a different scheme, trusted TLS certificate, host header, or external read-only tool.",
					"Continue with available evidence and record this metadata source as unavailable if it is not required for scope.",
				],
			});
		}
		return toolResult("API request completed", result.value);
	},
});

const vulnDbQueryTool = defineTool({
	name: "vuln_db_query",
	label: "Vulnerability DB Query",
	description: "Read-only CVE.org vulnerability lookup by CVE ID or keyword.",
	promptSnippet: "Look up CVE details or keyword matches in public vulnerability data.",
	promptGuidelines: [
		"Use vuln_db_query whenever a CVE ID, product/version, or known vulnerability question appears.",
		"Use results for defensive analysis and remediation. Do not generate exploit execution steps.",
	],
	parameters: Type.Object({
		source: Type.Optional(
			Type.Union([
				Type.Literal("cve"),
				Type.Literal("nvd"),
				Type.Literal("exploit_db"),
				Type.Literal("mitre_attack"),
				Type.Literal("all"),
			]),
		),
		cve_id: Type.Optional(Type.String({ description: "CVE ID such as CVE-2021-44228" })),
		query: Type.Optional(Type.String({ description: "Keyword, product/version, EDB id, or ATT&CK technique query" })),
		limit: Type.Optional(Type.Number({ description: "Maximum keyword matches, 1-20. Default 10." })),
	}),
	async execute(_toolCallId, params, signal) {
		const result = await queryVulnerabilityDb({
			source: params.source,
			cveId: params.cve_id,
			query: params.query,
			limit: params.limit,
			signal,
		});
		return toolResult("Vulnerability lookup completed", result);
	},
});

const createSecurityPortCheckTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_port_check",
		label: "Security Port Check",
		description:
			"Authorization-gated TCP connect port check for a single approved host. Bounded to 50 ports and no service exploitation.",
		promptSnippet: "Check a small approved set of TCP ports after explicit security authorization.",
		promptGuidelines: [
			"Use security_port_check only after security_scope_status confirms the target is in scope.",
			"Use ports from the explicit user request, authorized test plan, prior discovery output, or imported scanner result.",
			"Keep ports narrow and report results as observations, not proof of vulnerability.",
		],
		parameters: Type.Object({
			host: Type.String({ description: "Authorized host, domain, IP, or URL" }),
			ports: Type.Optional(
				Type.Array(Type.Number(), { description: "TCP ports to check from explicit input or prior tool output." }),
			),
			port_range: Type.Optional(
				Type.Object({
					start: Type.Number({ description: "First TCP port in an explicitly authorized range." }),
					end: Type.Number({ description: "Last TCP port in an explicitly authorized range." }),
				}),
			),
			timeout_ms: Type.Optional(Type.Number({ description: "Per-port timeout in milliseconds, 200-5000" })),
		}),
		async execute(_toolCallId, params, signal) {
			const host = extractHostname(params.host);
			assertAuthorizedTarget(authorization, host);
			const result = await checkTcpPorts({
				host,
				ports: params.ports,
				portRange: params.port_range,
				timeoutMs: params.timeout_ms,
				signal,
			});
			return toolResult(`Checked ${result.ports.length} TCP port(s) on ${result.host}`, result);
		},
	});

const createSecurityNetworkDiscoveryTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_network_discovery",
		label: "Security Network Discovery",
		description:
			"Authorization-gated host and service discovery using TCP connect checks. Supports common/web/full port profiles, no exploitation.",
		promptSnippet: "Discover live in-scope hosts and likely services with bounded TCP connect checks.",
		promptGuidelines: [
			"Use security_network_discovery only after security_scope_status confirms every expanded target is in scope.",
			"Keep CIDR ranges small; IPv4 CIDR discovery is limited to /24 through /32 and max_hosts defaults to 16.",
			"Use common or web port profiles for initial information gathering; use full 1-65535 discovery only after explicit user approval.",
			"Report open ports as observations requiring validation, not proof of vulnerability.",
		],
		parameters: Type.Object({
			targets: Type.Array(Type.String(), {
				description: "Authorized hosts, URLs, IPv4 addresses, or IPv4 CIDRs /24 through /32",
			}),
			ports: Type.Optional(
				Type.Array(Type.Number(), { description: "TCP ports to check from explicit input or prior tool output." }),
			),
			port_profile: Type.Optional(
				Type.Union([Type.Literal("common"), Type.Literal("web"), Type.Literal("full")], {
					description:
						"Automatic port set. Use full only when the user explicitly approves full TCP 1-65535 discovery.",
				}),
			),
			port_range: Type.Optional(
				Type.Object({
					start: Type.Number({ description: "First TCP port in an explicitly authorized range." }),
					end: Type.Number({ description: "Last TCP port in an explicitly authorized range." }),
				}),
			),
			timeout_ms: Type.Optional(
				Type.Number({ description: "Per-port timeout in milliseconds, 200-3000. Default 600." }),
			),
			max_hosts: Type.Optional(Type.Number({ description: "Maximum expanded hosts, 1-64. Default 16." })),
		}),
		async execute(_toolCallId, params, signal) {
			const hosts = expandDiscoveryTargets(params.targets, params.max_hosts);
			if (hosts.length === 0) {
				throw new Error("At least one valid discovery target is required.");
			}
			for (const host of hosts) {
				assertAuthorizedTarget(authorization, host);
			}
			const result = await discoverNetwork({
				targets: params.targets,
				ports: params.ports,
				portProfile: params.port_profile,
				portRange: params.port_range,
				timeoutMs: params.timeout_ms,
				maxHosts: params.max_hosts,
				signal,
			});
			return toolResult(`Discovered ${result.liveHosts.length} host(s) with open services`, result);
		},
	});

const createSecurityHeaderCheckTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_header_check",
		label: "Security Header Check",
		description: "Authorization-gated HTTP HEAD check for common defensive security headers on an approved URL.",
		promptSnippet: "Check common HTTP security headers on an approved URL.",
		promptGuidelines: [
			"Use security_header_check only for authorized HTTP or HTTPS targets.",
			"Treat missing headers as configuration findings that require context-specific remediation.",
		],
		parameters: Type.Object({
			url: Type.String({ description: "Authorized HTTP or HTTPS URL" }),
		}),
		async execute(_toolCallId, params, signal) {
			const host = extractHostname(params.url);
			assertAuthorizedTarget(authorization, host);
			try {
				const result = await checkSecurityHeaders(params.url, signal);
				return toolResult(`Checked security headers for ${result.url}`, result);
			} catch (error) {
				return toolResult(`Security header check failed for ${params.url}`, {
					url: params.url,
					ok: false,
					partial: true,
					error: toErrorMessage(error),
					recommendations: [
						"Use security_web_analysis to collect partial page/header evidence in one call.",
						"Use security_external_tool_runner with approved read-only tools such as curl, httpx, openssl s_client, or whatweb when Node fetch cannot inspect the service.",
					],
				});
			}
		},
	});

interface SecurityTerminalToolConfig {
	name: "security_terminal_session" | "security_external_tool_runner";
	label: string;
	description: string;
	promptSnippet: string;
	promptGuidelines: string[];
	resultPrefix: string;
}

const createSecurityTerminalTool = (
	authorization: SecurityAuthorizationStore | undefined,
	terminal: SecurityTerminalManager | undefined,
	config: SecurityTerminalToolConfig,
) =>
	defineTool({
		name: config.name,
		label: config.label,
		description: config.description,
		promptSnippet: config.promptSnippet,
		promptGuidelines: config.promptGuidelines,
		parameters: Type.Object({
			action: Type.Union([
				Type.Literal("open"),
				Type.Literal("exec"),
				Type.Literal("start"),
				Type.Literal("read"),
				Type.Literal("list"),
				Type.Literal("close"),
			]),
			session_id: Type.Optional(Type.String({ description: "Session id returned by action=open" })),
			command: Type.Optional(Type.String({ description: "Command to run for action=exec or action=start" })),
			cwd: Type.Optional(Type.String({ description: "Working directory for action=open" })),
			timeout_sec: Type.Optional(
				Type.Number({ description: "Command timeout in seconds for action=exec, 1-7200. Default 30." }),
			),
		}),
		async execute(_toolCallId, params) {
			if (!terminal) {
				throw new Error("Security terminal manager is unavailable.");
			}
			assertActiveAuthorization(authorization);
			if (params.action === "open") {
				return toolResult(`${config.resultPrefix} session opened`, await terminal.open(params.cwd));
			}
			if (params.action === "exec") {
				const command = params.command?.trim();
				if (!command) {
					throw new Error("command is required for action=exec.");
				}
				const result = await terminal.exec(params.session_id, command, params.timeout_sec);
				return toolResult(`${config.resultPrefix} command completed`, result);
			}
			if (params.action === "start") {
				const command = params.command?.trim();
				if (!command) {
					throw new Error("command is required for action=start.");
				}
				const result = await terminal.start(params.session_id, command);
				return toolResult(`${config.resultPrefix} command started`, result);
			}
			if (params.action === "read") {
				return toolResult(`${config.resultPrefix} output read`, terminal.read(params.session_id));
			}
			if (params.action === "list") {
				return toolResult(`${config.resultPrefix} sessions listed`, terminal.list());
			}
			return toolResult(`${config.resultPrefix} session closed`, await terminal.close(params.session_id ?? ""));
		},
	});

const createSecurityTerminalSessionTool = (
	authorization: SecurityAuthorizationStore | undefined,
	terminal: SecurityTerminalManager | undefined,
) =>
	createSecurityTerminalTool(authorization, terminal, {
		name: "security_terminal_session",
		label: "Security Terminal Session",
		description:
			"Authorization-gated persistent local terminal session for scoped security commands. Supports open, exec, start, read, list, and close.",
		promptSnippet: "Use a persistent local terminal session for authorized scoped security commands.",
		promptGuidelines: [
			"Use security_terminal_session only after an explicit security scope is active.",
			"Run commands only within the active user-approved targets, action categories, and duration.",
			"Prefer built-in security tools before terminal commands when a first-class tool exists.",
			"Use action=start for long-running commands such as full TCP 1-65535 Nmap scans, then poll with action=read until completion.",
		],
		resultPrefix: "Security terminal",
	});

const createSecurityExternalToolRunnerTool = (
	authorization: SecurityAuthorizationStore | undefined,
	terminal: SecurityTerminalManager | undefined,
) =>
	createSecurityTerminalTool(authorization, terminal, {
		name: "security_external_tool_runner",
		label: "Security External Tool Runner",
		description:
			"Authorization-gated runner for reviewed external security methods such as httpx, nmap, whatweb, katana, ffuf, and metadata import.",
		promptSnippet:
			"Run or import a reviewed external method after scope is active, using async start/read for long-running jobs.",
		promptGuidelines: [
			"Use security_external_tool_runner in attack surface analysis when a selected external method requires local execution or output import.",
			"Explain the external capability, target, command, expected output, limits, and evidence normalization before execution.",
			"Run commands only within the active user-approved targets, action categories, and duration.",
			"Use action=start for long-running service discovery, crawl, route discovery, or screenshot jobs, then poll with action=read until completion.",
		],
		resultPrefix: "Security external tool",
	});

const createSecurityPayloadModelPromptTool = (authorization: SecurityAuthorizationStore | undefined) =>
	defineTool({
		name: "security_payload_model_prompt",
		label: "Security Payload Model Prompt",
		description:
			"Builds the dedicated small-model configuration and prompts for authorized defensive payload or command candidate generation. Does not execute anything.",
		promptSnippet:
			"Prepare bounded payload/command generation prompts for the dedicated small security model, then review candidates before use.",
		promptGuidelines: [
			"Use security_payload_model_prompt only after security_scope_status confirms active authorization.",
			"Use the small model for candidate generation only; the main model must review scope, safety, and necessity before execution.",
			"Ask for explicit confirmation before any new target, broader port range, exploitation, or privilege-escalation scope.",
		],
		parameters: Type.Object({
			task: Type.Union([
				Type.Literal("http_request"),
				Type.Literal("injection_probe"),
				Type.Literal("scanner_command"),
				Type.Literal("manual_validation"),
				Type.Literal("safe_proof_of_impact"),
			]),
			objective: Type.String({ description: "Defensive validation objective" }),
			targets: Type.Array(Type.String({ description: "Authorized targets" })),
			authorized_actions: Type.Array(
				Type.String({ description: "Allowed action categories from active authorization" }),
			),
			constraints: Type.Optional(
				Type.Array(Type.String({ description: "Bounds such as rate limits, safe proof strings, no data writes" })),
			),
			evidence: Type.Optional(Type.Array(Type.String({ description: "Relevant evidence from prior steps" }))),
		}),
		async execute(_toolCallId, params) {
			assertActiveAuthorization(authorization);
			for (const target of params.targets) {
				assertAuthorizedTarget(authorization, extractHostname(target));
			}
			const result = buildSecurityPayloadPrompt({
				task: params.task,
				objective: params.objective,
				targets: params.targets,
				authorizedActions: params.authorized_actions,
				constraints: params.constraints,
				evidence: params.evidence,
			});
			return toolResult("Security payload model prompt prepared. Nothing was executed.", result);
		},
	});

const securityVulnerabilityAssessmentTool = defineTool({
	name: "security_vulnerability_assessment",
	label: "Security Vulnerability Assessment",
	description:
		"Correlates supplied discovery, HTTP header, and vulnerability database evidence into defensive findings without running scans.",
	promptSnippet: "Convert collected evidence into defensive vulnerability findings before report generation.",
	promptGuidelines: [
		"Use security_vulnerability_assessment after collecting discovery, header, or vulnerability database evidence.",
		"Do not invent evidence. Include limitations when evidence is incomplete or product/version matching is uncertain.",
		"Use the generated findings as input to security_report when the user requests a report.",
	],
	parameters: Type.Object({
		scope: Type.Array(Type.String(), { description: "Targets or assets covered by the supplied evidence" }),
		discovered_hosts: Type.Optional(
			Type.Array(
				Type.Object({
					host: Type.String({ description: "Discovered host" }),
					open_services: Type.Array(
						Type.Object({
							port: Type.Number({ description: "Open TCP port" }),
							service: Type.String({ description: "Likely service name" }),
							status: Type.Literal("open"),
						}),
					),
					open_count: Type.Optional(Type.Number({ description: "Number of open services" })),
				}),
			),
		),
		header_checks: Type.Optional(
			Type.Array(
				Type.Object({
					url: Type.String({ description: "Checked HTTP or HTTPS URL" }),
					status: Type.Number({ description: "HTTP response status" }),
					headers: Type.Object({
						present: Type.Array(Type.String(), { description: "Observed security headers" }),
						missing: Type.Array(Type.String(), { description: "Missing security headers" }),
					}),
					score: Type.Number({ description: "Header score from 0 to 100" }),
				}),
			),
		),
		vulnerabilities: Type.Optional(
			Type.Array(
				Type.Object({
					vuln_id: Type.String({ description: "CVE, EDB, ATT&CK, or other vulnerability identifier" }),
					source: Type.Optional(
						Type.Union([
							Type.Literal("cve"),
							Type.Literal("nvd"),
							Type.Literal("exploit_db"),
							Type.Literal("mitre_attack"),
							Type.Literal("scan"),
						]),
					),
					title: Type.Optional(Type.String({ description: "Vulnerability title" })),
					description: Type.Optional(Type.String({ description: "Vulnerability description" })),
					severity: Type.Optional(
						Type.Union([
							Type.Literal("critical"),
							Type.Literal("high"),
							Type.Literal("medium"),
							Type.Literal("low"),
							Type.Literal("info"),
							Type.Literal("unknown"),
						]),
					),
					cvss_score: Type.Optional(Type.Union([Type.Number(), Type.Null()])),
					references: Type.Optional(Type.Array(Type.String(), { description: "Reference URLs or IDs" })),
					affected_software: Type.Optional(
						Type.Array(
							Type.Object({
								vendor: Type.String(),
								product: Type.String(),
								versions: Type.Array(Type.String()),
							}),
						),
					),
				}),
			),
		),
	}),
	async execute(_toolCallId, params) {
		const result = assessVulnerabilities({
			scope: params.scope,
			discoveredHosts: params.discovered_hosts?.map((host) => ({
				host: host.host,
				openServices: host.open_services.map((service) => ({
					port: service.port,
					service: service.service,
					status: service.status,
				})),
				openCount: host.open_count ?? host.open_services.length,
			})),
			headerChecks: params.header_checks,
			vulnerabilities: params.vulnerabilities?.map((vulnerability) => ({
				vulnId: vulnerability.vuln_id,
				source: vulnerability.source ?? "scan",
				title: vulnerability.title ?? vulnerability.vuln_id,
				description: vulnerability.description ?? "",
				affectedSoftware: vulnerability.affected_software ?? [],
				severity: vulnerability.severity ?? "unknown",
				cvssScore: vulnerability.cvss_score ?? null,
				cvssVector: null,
				exploits: [],
				attackTechniques: [],
				mitigations: [],
				references: vulnerability.references ?? [],
				tags: [],
				datePublished: null,
				dateModified: null,
				state: "",
				rawData: null,
			})),
		});
		return toolResult(`Assessed ${result.summary.totalFindings} defensive finding(s)`, result);
	},
});

const securityAssessmentTool = defineTool({
	name: "security_assessment",
	label: "Security Assessment",
	description:
		"Correlates supplied discovery, attack surface, scanner, and vulnerability metadata evidence into defensive findings without running scans.",
	promptSnippet: "Convert collected security evidence into defensive findings before report generation.",
	promptGuidelines: [
		"Use security_assessment after collecting discovery, attack surface, scanner, or vulnerability metadata evidence.",
		"Do not invent evidence. Include limitations when evidence is incomplete or product/version matching is uncertain.",
		"Use the generated findings as input to security_report when the user requests a report.",
	],
	parameters: Type.Object({
		scope: Type.Array(Type.String(), { description: "Targets or assets covered by the supplied evidence" }),
		discovered_hosts: Type.Optional(
			Type.Array(
				Type.Object({
					host: Type.String({ description: "Discovered host" }),
					open_services: Type.Array(
						Type.Object({
							port: Type.Number({ description: "Open TCP port" }),
							service: Type.String({ description: "Likely service name" }),
							status: Type.Literal("open"),
						}),
					),
					open_count: Type.Optional(Type.Number({ description: "Number of open services" })),
				}),
			),
		),
		header_checks: Type.Optional(
			Type.Array(
				Type.Object({
					url: Type.String({ description: "Checked HTTP or HTTPS URL" }),
					status: Type.Number({ description: "HTTP response status" }),
					headers: Type.Object({
						present: Type.Array(Type.String(), { description: "Observed security headers" }),
						missing: Type.Array(Type.String(), { description: "Missing security headers" }),
					}),
					score: Type.Number({ description: "Header score from 0 to 100" }),
				}),
			),
		),
		vulnerabilities: Type.Optional(
			Type.Array(
				Type.Object({
					vuln_id: Type.String({ description: "CVE, EDB, ATT&CK, or other vulnerability identifier" }),
					source: Type.Optional(
						Type.Union([
							Type.Literal("cve"),
							Type.Literal("nvd"),
							Type.Literal("exploit_db"),
							Type.Literal("mitre_attack"),
							Type.Literal("scan"),
						]),
					),
					title: Type.Optional(Type.String({ description: "Vulnerability title" })),
					description: Type.Optional(Type.String({ description: "Vulnerability description" })),
					severity: Type.Optional(
						Type.Union([
							Type.Literal("critical"),
							Type.Literal("high"),
							Type.Literal("medium"),
							Type.Literal("low"),
							Type.Literal("info"),
							Type.Literal("unknown"),
						]),
					),
					cvss_score: Type.Optional(Type.Union([Type.Number(), Type.Null()])),
					references: Type.Optional(Type.Array(Type.String(), { description: "Reference URLs or IDs" })),
					affected_software: Type.Optional(
						Type.Array(
							Type.Object({
								vendor: Type.String(),
								product: Type.String(),
								versions: Type.Array(Type.String()),
							}),
						),
					),
				}),
			),
		),
	}),
	async execute(_toolCallId, params) {
		const result = assessVulnerabilities({
			scope: params.scope,
			discoveredHosts: params.discovered_hosts?.map((host) => ({
				host: host.host,
				openServices: host.open_services.map((service) => ({
					port: service.port,
					service: service.service,
					status: service.status,
				})),
				openCount: host.open_count ?? host.open_services.length,
			})),
			headerChecks: params.header_checks,
			vulnerabilities: params.vulnerabilities?.map((vulnerability) => ({
				vulnId: vulnerability.vuln_id,
				source: vulnerability.source ?? "scan",
				title: vulnerability.title ?? vulnerability.vuln_id,
				description: vulnerability.description ?? "",
				affectedSoftware: vulnerability.affected_software ?? [],
				severity: vulnerability.severity ?? "unknown",
				cvssScore: vulnerability.cvss_score ?? null,
				cvssVector: null,
				exploits: [],
				attackTechniques: [],
				mitigations: [],
				references: vulnerability.references ?? [],
				tags: [],
				datePublished: null,
				dateModified: null,
				state: "",
				rawData: null,
			})),
		});
		return toolResult(`Assessed ${result.summary.totalFindings} defensive finding(s)`, result);
	},
});

const securityDetectionAnalysisTool = defineTool({
	name: "security_detection_analysis",
	label: "Security Detection Analysis",
	description:
		"Analyzes supplied logs, alerts, or network flow events for defensive intrusion-detection indicators without live monitoring.",
	promptSnippet:
		"Analyze provided security events for authentication bursts, scanning, web attack, and malware indicators.",
	promptGuidelines: [
		"Use security_detection_analysis when the user provides logs, alerts, SIEM snippets, firewall events, or flow summaries.",
		"Treat detections as heuristic indicators that require validation against asset context and baseline behavior.",
		"Do not claim live monitoring or incident containment was performed unless separate evidence shows it.",
	],
	parameters: Type.Object({
		events: Type.Array(
			Type.Object({
				timestamp: Type.Optional(Type.String({ description: "Event timestamp" })),
				source: Type.String({ description: "Log source, sensor, or system name" }),
				event_type: Type.String({ description: "Event type such as auth, firewall, connection, http, process" }),
				message: Type.String({ description: "Raw or normalized event message" }),
				severity: Type.Optional(
					Type.Union([
						Type.Literal("critical"),
						Type.Literal("high"),
						Type.Literal("medium"),
						Type.Literal("low"),
						Type.Literal("info"),
					]),
				),
				src_ip: Type.Optional(Type.String({ description: "Source IP address" })),
				dest_ip: Type.Optional(Type.String({ description: "Destination IP address" })),
				dest_port: Type.Optional(Type.Number({ description: "Destination TCP/UDP port" })),
				username: Type.Optional(Type.String({ description: "Username associated with the event" })),
			}),
			{ description: "Security events to analyze. Max 500 are evaluated." },
		),
	}),
	async execute(_toolCallId, params) {
		const result = analyzeDetections({
			events: params.events.map((event) => ({
				timestamp: event.timestamp,
				source: event.source,
				eventType: event.event_type,
				message: event.message,
				severity: event.severity,
				srcIp: event.src_ip,
				destIp: event.dest_ip,
				destPort: event.dest_port,
				username: event.username,
			})),
		});
		return toolResult(`Analyzed ${result.summary.totalEvents} security event(s)`, result);
	},
});

const createSecurityReportTool = (memory: SecurityMemoryStore | undefined) =>
	defineTool({
		name: "security_report",
		label: "Security Report",
		description:
			"Assembles structured defensive security findings into Markdown/JSON and can save the report under reports/.",
		promptSnippet: "Generate a structured defensive security report from collected evidence and findings.",
		promptGuidelines: [
			"Use security_report after evidence collection or when the user requests a security report.",
			"Keep findings evidence-based. Do not invent scan results or claim exploitation was performed.",
		],
		parameters: Type.Object({
			title: Type.Optional(Type.String({ description: "Report title" })),
			scope: Type.Array(Type.String(), { description: "Targets or assets covered by the report" }),
			methodology: Type.Optional(Type.Array(Type.String(), { description: "Assessment steps performed" })),
			findings: Type.Optional(
				Type.Array(
					Type.Object({
						title: Type.String({ description: "Finding title" }),
						severity: Type.Optional(
							Type.Union([
								Type.Literal("info"),
								Type.Literal("low"),
								Type.Literal("medium"),
								Type.Literal("high"),
								Type.Literal("critical"),
							]),
						),
						asset: Type.Optional(Type.String({ description: "Affected asset" })),
						evidence: Type.Optional(Type.String({ description: "Observed evidence" })),
						impact: Type.Optional(Type.String({ description: "Security impact" })),
						remediation: Type.Optional(Type.String({ description: "Recommended remediation" })),
						references: Type.Optional(Type.Array(Type.String(), { description: "Reference URLs or IDs" })),
					}),
				),
			),
			limitations: Type.Optional(Type.Array(Type.String(), { description: "Assessment limitations" })),
			save_to_reports: Type.Optional(
				Type.Boolean({
					description: "When true, save Markdown and JSON report files under the current cwd reports/ directory.",
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const result = assembleSecurityReport({
				title: params.title,
				scope: params.scope,
				methodology: params.methodology,
				findings: params.findings,
				limitations: params.limitations,
			});
			const saved = params.save_to_reports ? saveSecurityReport(ctx.cwd, result) : undefined;
			memory?.remember({
				content: summarizeReportForMemory(result, saved?.markdownPath),
				type: "episodic",
				importance: 0.9,
				metadata: {
					kind: "security_report_summary",
					scope: result.scope,
					reportPath: saved?.markdownPath,
					totalFindings: result.summary.totalFindings,
					bySeverity: result.summary.bySeverity,
				},
			});
			return toolResult(saved ? "Security report assembled and saved" : "Security report assembled", {
				...result,
				saved,
			});
		},
	});

function inferAuthIndicators(page: PageExtractResult | null): string[] {
	if (!page) return [];
	const evidence = [
		page.title,
		...Object.entries(page.meta ?? {}).map(([key, value]) => `${key} ${value}`),
		...(page.links ?? []).flatMap((link) => [link.text, link.url]),
	]
		.join("\n")
		.toLowerCase();
	const indicators = [
		{ token: "login", label: "login" },
		{ token: "signin", label: "sign-in" },
		{ token: "sign in", label: "sign-in" },
		{ token: "oauth", label: "oauth" },
		{ token: "saml", label: "saml" },
		{ token: "admin", label: "admin" },
		{ token: "account", label: "account" },
		{ token: "auth", label: "auth" },
	];
	return [
		...new Set(
			indicators.filter((indicator) => evidence.includes(indicator.token)).map((indicator) => indicator.label),
		),
	];
}

function toErrorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function toolResult(summary: string, details: unknown) {
	return {
		content: [{ type: "text" as const, text: `${summary}\n\n${JSON.stringify(details, null, 2).slice(0, 12000)}` }],
		details,
	};
}

function assertAuthorizedTarget(authorization: SecurityAuthorizationStore | undefined, target: string): void {
	if (!authorization) {
		throw new Error("Security authorization store is unavailable.");
	}
	if (!authorization.isTargetAuthorized(target)) {
		throw new Error(`Target is not in the active security authorization scope: ${target}`);
	}
}

function assertActiveAuthorization(authorization: SecurityAuthorizationStore | undefined): void {
	if (!authorization) {
		throw new Error("Security authorization store is unavailable.");
	}
	if (!authorization.status().authorized) {
		throw new Error("No active security authorization scope.");
	}
}

function saveSecurityReport(cwd: string, report: ReturnType<typeof assembleSecurityReport>) {
	const reportsDir = join(cwd, "reports");
	if (!existsSync(reportsDir)) {
		mkdirSync(reportsDir, { recursive: true });
	}
	const baseName = `${report.generatedAt.replace(/[:.]/g, "-")}-security-report`;
	const markdownPath = join(reportsDir, `${baseName}.md`);
	const jsonPath = join(reportsDir, `${baseName}.json`);
	writeFileSync(markdownPath, report.markdown, { encoding: "utf-8", mode: 0o600 });
	writeFileSync(jsonPath, JSON.stringify(report, null, 2), { encoding: "utf-8", mode: 0o600 });
	return { markdownPath, jsonPath };
}

function summarizeReportForMemory(
	report: ReturnType<typeof assembleSecurityReport>,
	markdownPath: string | undefined,
): string {
	const severitySummary = Object.entries(report.summary.bySeverity)
		.filter(([, count]) => count > 0)
		.map(([severity, count]) => `${severity}:${count}`)
		.join(", ");
	const findings = report.findings
		.slice(0, 5)
		.map((finding) => `${finding.severity} ${finding.asset}: ${finding.title}`)
		.join("; ");
	return [
		`Security report generated for scope ${report.scope.join(", ")}.`,
		`Findings: total=${report.summary.totalFindings}${severitySummary ? ` (${severitySummary})` : ""}.`,
		findings ? `Top findings: ${findings}.` : "Top findings: none.",
		markdownPath ? `Report path: ${markdownPath}.` : "",
	]
		.filter(Boolean)
		.join(" ");
}
