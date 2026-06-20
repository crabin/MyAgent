import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createAgentSessionServices } from "../src/core/agent-session-services.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ExtensionRunner } from "../src/core/extensions/index.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { ASSET_DISCOVERY_SUBAGENT } from "../src/core/subagent/asset-discovery/index.ts";
import { ATTACK_SURFACE_ANALYSIS_SUBAGENT } from "../src/core/subagent/attack-surface-analysis/index.ts";
import { POC_RESEARCH_SUBAGENT } from "../src/core/subagent/poc-research/index.ts";
import {
	analyzeDetections,
	assembleSecurityReport,
	assessVulnerabilities,
	buildSecurityPayloadPrompt,
	buildSecurityStepExecutionPlan,
	buildSecuritySubagentIterationPlan,
	buildSecurityWorkflowPlan,
	buildVulnerabilityEmbeddingText,
	checkTcpPorts,
	classifySecurityIntent,
	clearSecuritySessionMemory,
	createSecurityAuthorizationStore,
	createSecurityMemoryStore,
	createSecuritySubagentExtension,
	createSecuritySubagentTools,
	createSecurityTerminalManager,
	createUnifiedVulnerability,
	expandDiscoveryTargets,
	normalizeExploitDbRow,
	normalizeMitreAttackObject,
	normalizeNvdItem,
	runSecurityExploration,
	SECURITY_DEDICATED_SUBAGENTS,
	type SecurityExploreDeps,
	vulnerabilityToSummary,
} from "../src/core/subagent/security/index.ts";
import { createTestExtensionsResult } from "./utilities.ts";

describe("security subagent", () => {
	it("classifies vulnerability scanning requests as authorized security tasks", () => {
		const decision = classifySecurityIntent("对 https://example.com 做一次授权漏洞扫描并生成报告");
		expect(decision.intent).toBe("security_task_complex");
		expect(decision.needsAuthorization).toBe(true);
		expect(decision.needsExplore).toBe(true);
		expect(decision.needsReport).toBe(true);
		expect(decision.focus).toContain("https://example.com");
	});

	it("asks for clarification when a security task has no target", () => {
		const decision = classifySecurityIntent("帮我做一次网络安全测试");
		expect(decision.intent).toBe("security_task_clarify");
		expect(decision.needsAuthorization).toBe(true);
	});

	it("leaves unrelated prompts untouched", () => {
		const decision = classifySecurityIntent("write a changelog entry");
		expect(decision.intent).toBe("not_security");
		expect(decision.needsAuthorization).toBe(false);
	});

	it("injects security subagent context for matching prompts", async () => {
		const tempDir = mkdtempSync(join(tmpdir(), "pi-security-subagent-runner-"));
		try {
			const result = await createTestExtensionsResult([createSecuritySubagentExtension], tempDir);
			const sessionManager = SessionManager.inMemory();
			const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
			const modelRegistry = ModelRegistry.create(authStorage);
			const runner = new ExtensionRunner(result.extensions, result.runtime, tempDir, sessionManager, modelRegistry);

			const emitted = await runner.emitBeforeAgentStart(
				"scan https://example.com for exposed services",
				undefined,
				"base prompt",
				{ cwd: tempDir },
			);

			expect(emitted?.systemPrompt).toContain("Security Subagent Mode");
			expect(emitted?.systemPrompt).toContain("Require explicit authorization");
			expect(emitted?.systemPrompt).toContain("vuln_db_query");
			expect(emitted?.systemPrompt).toContain("smart_search");
			expect(emitted?.systemPrompt).toContain("security_research");
			expect(emitted?.systemPrompt).toContain("security_memory");
			expect(emitted?.systemPrompt).toContain("security_workflow_plan");
			expect(emitted?.systemPrompt).toContain("security_user_approval");
			expect(emitted?.systemPrompt).toContain("Enter approves the highlighted option");
			expect(emitted?.systemPrompt).toContain("security_step_execution_plan");
			expect(emitted?.systemPrompt).toContain("security_delegate_subagent");
			expect(emitted?.systemPrompt).toContain("security_subagent_iteration_plan");
			expect(emitted?.systemPrompt).toContain("operatorChoicePrompt");
			expect(emitted?.systemPrompt).toContain("readyForNextPhase");
			expect(emitted?.systemPrompt).toContain("security_web_analysis");
			expect(emitted?.systemPrompt).toContain("security_crawl");
			expect(emitted?.systemPrompt).toContain("security_explore");
			expect(emitted?.systemPrompt).toContain("security_port_check");
			expect(emitted?.systemPrompt).toContain("security_network_discovery");
			expect(emitted?.systemPrompt).toContain("security_external_tool_runner");
			expect(emitted?.systemPrompt).toContain("security_terminal_session");
			expect(emitted?.systemPrompt).toContain("security_payload_model_prompt");
			expect(emitted?.systemPrompt).toContain("security_detection_analysis");
			expect(emitted?.systemPrompt).toContain("security_assessment");
			expect(emitted?.systemPrompt).toContain("security_vulnerability_assessment");
			expect(emitted?.systemPrompt).toContain("security_report");
			expect(emitted?.systemPrompt).toContain("Delegate asset discovery, attack surface analysis, and PoC research");
			expect(emitted?.systemPrompt).toContain("corresponding PoC references");
			expect(emitted?.systemPrompt).toContain("Security Context Usage");
			expect(emitted?.messages?.[0]?.customType).toBe("security_subagent");
			expect(JSON.stringify(emitted?.messages?.[0]?.details)).toContain("contextUsage");
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("defines read-only security research tools", () => {
		const toolNames = createSecuritySubagentTools().map((tool) => tool.name);
		expect(toolNames).toEqual([
			"security_authorize_scope",
			"security_user_approval",
			"security_scope_status",
			"security_memory",
			"security_workflow_plan",
			"security_delegate_subagent",
			"security_subagent_iteration_plan",
			"security_step_execution_plan",
			"security_research",
			"security_web_analysis",
			"security_explore",
			"smart_search",
			"page_extract",
			"security_crawl",
			"deep_crawl",
			"api_client",
			"vuln_db_query",
			"security_port_check",
			"security_network_discovery",
			"security_header_check",
			"security_external_tool_runner",
			"security_terminal_session",
			"security_payload_model_prompt",
			"security_detection_analysis",
			"security_assessment",
			"security_vulnerability_assessment",
			"security_report",
		]);
	});

	it("tracks explicit authorization scope without running scans", () => {
		const store = createSecurityAuthorizationStore();
		const now = new Date("2026-06-16T00:00:00.000Z");
		const status = store.authorize({
			targets: ["https://Example.com"],
			allowedActions: ["bounded_active_scan"],
			reason: "Internal assessment ticket SEC-123",
			now,
		});

		expect(status.authorized).toBe(true);
		expect(status.scope?.targets).toEqual(["example.com"]);
		expect(store.isTargetAuthorized("app.example.com", now)).toBe(true);
		expect(store.isTargetAuthorized("example.org", now)).toBe(false);
	});

	it("expires authorization scope", () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({
			targets: ["example.com"],
			expiresAt: "2026-06-16T01:00:00.000Z",
			now: new Date("2026-06-16T00:00:00.000Z"),
		});

		expect(store.status(new Date("2026-06-16T02:00:00.000Z")).authorized).toBe(false);
	});

	it("stores recalls and assembles security memory context", () => {
		const memory = createSecurityMemoryStore();
		memory.remember({
			content: "example.com assessment found missing Content-Security-Policy header",
			type: "episodic",
			importance: 0.8,
			now: new Date("2026-06-16T00:00:00.000Z"),
		});
		memory.remember({
			content: "Prefer HEAD checks before deeper web crawling",
			type: "long_term",
			importance: 0.6,
			now: new Date("2026-06-16T00:01:00.000Z"),
		});

		const recalled = memory.recall({ query: "example.com csp", limit: 3 });
		expect(recalled[0]?.content).toContain("Content-Security-Policy");

		const context = memory.context({ query: "example.com", budgetTokens: 200 });
		expect(context.contextBlock).toContain("Security Memory Context");
		expect(context.debug.selectedCount).toBeGreaterThan(0);
	});

	it("persists and reloads security memory snapshots with semantic recall", () => {
		const tempDir = mkdtempSync(join(tmpdir(), "pi-security-memory-"));
		try {
			const path = join(tempDir, "memory.json");
			const memory = createSecurityMemoryStore();
			memory.remember({
				content: "example.com assessment observed a missing Content-Security-Policy response header",
				type: "long_term",
				importance: 0.9,
				now: new Date("2026-06-16T00:00:00.000Z"),
			});
			const saved = memory.saveToFile(path);
			expect(saved.itemCount).toBe(1);

			const loaded = createSecurityMemoryStore();
			const result = loaded.loadFromFile(path);
			expect(result.stats.longTermCount).toBe(1);
			expect(loaded.recall({ query: "response header policy", limit: 1 })[0]?.content).toContain(
				"Content-Security-Policy",
			);
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("exposes security memory as a tool", async () => {
		const memory = createSecurityMemoryStore();
		const memoryTool = createSecuritySubagentTools(undefined, undefined, memory).find(
			(tool) => tool.name === "security_memory",
		);
		if (!memoryTool) throw new Error("security_memory tool not found");

		await memoryTool.execute(
			"call-1",
			{
				action: "remember",
				content: "localhost is authorized for a bounded defensive check",
				memory_type: "short_term",
			},
			undefined,
			undefined,
			undefined as never,
		);
		const recalled = await memoryTool.execute(
			"call-2",
			{ action: "recall", query: "localhost" },
			undefined,
			undefined,
			undefined as never,
		);
		expect(JSON.stringify(recalled.details)).toContain("localhost is authorized");
	});

	it("persists security memory through the tool into the session directory", async () => {
		const tempDir = mkdtempSync(join(tmpdir(), "pi-security-memory-tool-"));
		try {
			const memory = createSecurityMemoryStore();
			const memoryTool = createSecuritySubagentTools(undefined, undefined, memory).find(
				(tool) => tool.name === "security_memory",
			);
			if (!memoryTool) throw new Error("security_memory tool not found");
			const ctx = { sessionManager: { getSessionDir: () => tempDir } };

			await memoryTool.execute(
				"call-1",
				{ action: "remember", content: "example.com authorization ticket SEC-123", memory_type: "episodic" },
				undefined,
				undefined,
				ctx as never,
			);
			const persisted = await memoryTool.execute(
				"call-2",
				{ action: "persist" },
				undefined,
				undefined,
				ctx as never,
			);

			expect(JSON.stringify(persisted.details)).toContain("security-subagent-memory.json");
			expect(existsSync(join(tempDir, "security-subagent-memory.json"))).toBe(true);
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("clears the current session security memory file", () => {
		const tempDir = mkdtempSync(join(tmpdir(), "pi-security-memory-clear-"));
		try {
			const path = join(tempDir, "security-subagent-memory.json");
			writeFileSync(path, JSON.stringify({ version: 1, items: [] }));

			const result = clearSecuritySessionMemory({ sessionManager: { getSessionDir: () => tempDir } });

			expect(result.path).toBe(path);
			expect(result.deleted).toBe(true);
			expect(existsSync(path)).toBe(false);
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("plans complex security work as gated multi-agent coordination", () => {
		const plan = buildSecurityWorkflowPlan({
			objective: "对 https://example.com 做授权漏洞扫描并生成报告",
			targets: ["https://example.com"],
			authorizationConfirmed: false,
			complexity: "complex",
		});

		expect(plan.mode).toBe("multi_agent_coordination");
		expect(plan.authorizationRequired).toBe(true);
		expect(plan.steps.map((step) => step.id)).toContain("confirm-scope");
		expect(plan.steps.map((step) => step.id)).toContain("asset-discovery");
		expect(plan.steps.map((step) => step.id)).toContain("vulnerability-scanning");
		expect(plan.steps.map((step) => step.id)).toContain("manual-validation");
		expect(plan.steps.find((step) => step.id === "asset-discovery")?.requiresAuthorization).toBe(true);
		expect(plan.steps.find((step) => step.id === "asset-discovery")?.agentRole).toBe("asset_discovery_agent");
		expect(plan.steps.find((step) => step.id === "asset-discovery")?.dedicatedSubagent).toBe("asset_discovery");
		expect(plan.steps.find((step) => step.id === "attack-surface-analysis")?.agentRole).toBe(
			"attack_surface_analysis_agent",
		);
		expect(plan.steps.find((step) => step.id === "attack-surface-analysis")?.dedicatedSubagent).toBe(
			"attack_surface_analysis",
		);
		expect(plan.steps.find((step) => step.id === "vulnerability-scanning")?.agentRole).toBe("poc_research_agent");
		expect(plan.steps.find((step) => step.id === "vulnerability-scanning")?.dedicatedSubagent).toBe("poc_research");
		expect(plan.dedicatedSubagents.map((subagent) => subagent.name)).toEqual([
			"asset_discovery",
			"attack_surface_analysis",
			"poc_research",
		]);
		expect(plan.steps.find((step) => step.id === "asset-discovery")?.tools).not.toContain(
			"security_network_discovery",
		);
		expect(plan.steps.find((step) => step.id === "asset-discovery")?.tools).toContain("security_delegate_subagent");
		expect(plan.steps.find((step) => step.id === "asset-discovery")?.stepPrompt).toContain("asset baseline");
		expect(plan.steps.find((step) => step.id === "asset-discovery")?.toolCallPlan.map((tool) => tool.tool)).toContain(
			"security_research",
		);
		expect(
			plan.steps.find((step) => step.id === "asset-discovery")?.toolCallPlan.map((tool) => tool.tool),
		).not.toContain("smart_search");
		expect(
			plan.steps.find((step) => step.id === "asset-discovery")?.toolCallPlan.map((tool) => tool.tool),
		).not.toContain("security_explore");
		expect(plan.steps.find((step) => step.id === "vulnerability-scanning")?.stepPrompt).toContain(
			"services, middleware",
		);
		expect(plan.steps.find((step) => step.id === "vulnerability-scanning")?.tools).toContain("security_research");
		expect(plan.steps.find((step) => step.id === "vulnerability-scanning")?.tools).toContain("security_assessment");
		expect(plan.steps.find((step) => step.id === "vulnerability-scanning")?.tools).toContain("security_report");
		expect(plan.steps.find((step) => step.id === "vulnerability-scanning")?.reportAfterStep).toBe(true);
		expect(plan.steps.find((step) => step.id === "vulnerability-exploitation")?.tools).toContain(
			"security_payload_model_prompt",
		);
		expect(
			plan.steps
				.find((step) => step.id === "attack-surface-analysis")
				?.externalToolPrompts.map((prompt) => prompt.tool),
		).toContain("Service Discovery");
		expect(
			plan.steps
				.find((step) => step.id === "vulnerability-scanning")
				?.externalToolPrompts.map((prompt) => prompt.tool),
		).toContain("Network and application scanner import");
		expect(
			plan.steps.find((step) => step.id === "manual-validation")?.externalToolPrompts.map((prompt) => prompt.tool),
		).toContain("Burp Suite");
		expect(
			plan.steps
				.find((step) => step.id === "privilege-escalation")
				?.externalToolPrompts.map((prompt) => prompt.tool),
		).toContain("BloodHound");
		expect(plan.recommendedAuthorizationScope.portScope).toContain("1-65535");
		expect(plan.safetyBoundaries.join("\n")).toContain("No security tool or command execution");
	});

	it("builds phase-specific execution plans from prior results and missing information", () => {
		const plan = buildSecurityStepExecutionPlan({
			phase: "vulnerability_scanning",
			objective: "Assess https://example.com",
			targets: ["https://example.com"],
			authorizationConfirmed: true,
			priorResults: [
				"asset discovery found example.com open services 80/http and 443/https",
				"attack surface analysis found nginx 1.24 and missing Content-Security-Policy",
			],
			missingInformation: ["service versions where available"],
		});

		expect(plan.stepId).toBe("vulnerability-scanning");
		expect(plan.stepPrompt).toContain("Prior results to use");
		expect(plan.stepPrompt).toContain("Dedicated subagent: PoC Research Subagent");
		expect(plan.dedicatedSubagent?.name).toBe("poc_research");
		expect(plan.subagentDispatch?.subagent).toBe("poc_research");
		expect(plan.subagentDispatch?.displayName).toBe("PoC Research Subagent");
		expect(plan.subagentDispatch?.externalToolCalls.map((tool) => tool.method)).toContain(
			"Exploit and public PoC references",
		);
		expect(plan.subagentDispatch?.executionDirectives.join("\n")).toContain(
			"Run this phase as PoC Research Subagent",
		);
		expect(plan.requiredInformation).toContain("observed services and middleware");
		expect(plan.selectedToolCalls.map((tool) => tool.tool)).toEqual([
			"security_user_approval",
			"security_delegate_subagent",
			"security_subagent_iteration_plan",
			"security_scope_status",
			"security_memory",
			"api_client",
			"security_research",
			"security_assessment",
			"security_report",
		]);
		expect(
			plan.selectedToolCalls.find((tool) => tool.tool === "security_research")?.inputsNeeded.join("\n"),
		).toContain("observed service or middleware");
		expect(plan.approvalPrompt?.options).toEqual([
			"Approve",
			"Approve all next-phase requests this session",
			"Reject",
			"人工建议",
		]);
		expect(plan.approvalPrompt?.message).toContain("Enter approves");
		expect(plan.approvalPrompt?.message).toContain("人工建议");
		expect(plan.reportRequiredAfterStep).toBe(true);
		expect(plan.nextDecisionInputs).toContain("saved report paths");
		expect(plan.externalToolPrompts.map((prompt) => prompt.tool)).toContain("Network and application scanner import");
		expect(plan.externalToolPrompts.map((prompt) => prompt.tool)).toContain("Supply-chain and code scanner import");
		expect(
			plan.externalToolPrompts.find((prompt) => prompt.tool === "Network and application scanner import")?.prompt,
		).toContain("External tool/method: Network and application scanner import");
		expect(
			plan.externalToolPrompts
				.find((prompt) => prompt.tool === "Supply-chain and code scanner import")
				?.safetyConstraints.join("\n"),
		).toContain("authorized targets");
	});

	it("delegates dedicated workflow nodes to their matching subagent contracts", async () => {
		const delegateTool = createSecuritySubagentTools().find((tool) => tool.name === "security_delegate_subagent");
		if (!delegateTool) throw new Error("security_delegate_subagent tool not found");

		const result = await delegateTool.execute(
			"call-1",
			{
				subagent: "asset_discovery",
				phase: "asset_discovery",
				objective: "Collect assets for example.com",
				targets: ["example.com"],
				prior_results: ["customer supplied example.com as authorized root domain"],
				missing_information: ["asset inventory if supplied"],
			},
			undefined,
			undefined,
			undefined as never,
		);

		const text = result.content[0]?.type === "text" ? result.content[0].text : "";
		const details = JSON.stringify(result.details);
		expect(text).toContain("Asset Discovery Subagent delegated");
		expect(details).toContain('"subagent":"asset_discovery"');
		expect(details).toContain("externalToolCalls");
		expect(details).toContain("initialIterationPlan");
		expect(details).toContain('"decision":"continue"');
		expect(details).toContain("Customer-provided asset inventory");
		expect(details).toContain("primary asset collection plan");
	});

	it("plans dedicated subagent iterations until completion or manual intervention", () => {
		const first = buildSecuritySubagentIterationPlan({
			subagent: "asset_discovery",
			phase: "asset_discovery",
			objective: "Collect assets for example.com",
			targets: ["example.com"],
			priorResults: ["authorized target example.com"],
			missingInformation: ["asset inventory", "source references"],
			iteration: 1,
		});

		expect(first.decision).toBe("continue");
		expect(first.nextToolCalls.map((tool) => tool.tool)).toContain("security_scope_status");
		expect(first.nextExternalMethods.map((method) => method.tool)).toContain("Customer-provided asset inventory");
		expect(first.fallbackActions.join("\n")).toContain("manual intervention");
		expect(first.memoryActions.join("\n")).toContain("security_memory");
		expect(first.operatorChoicePrompt.options).toContain("Continue collecting");
		expect(first.operatorChoicePrompt.options).toContain("人工建议");
		expect(first.operatorChoicePrompt.message).toContain("Tab");

		const needsMemory = buildSecuritySubagentIterationPlan({
			subagent: "attack_surface_analysis",
			phase: "attack_surface_analysis",
			objective: "Map surface for example.com",
			targets: ["example.com"],
			collectedEvidence: [
				"attack surface map covers exposed services, technology/service inventory, entry points, and evidence gaps",
				"handoff includes services, middleware, product/version evidence, HTTP/API entry points, authentication boundaries, and configuration observations",
			],
			iteration: 2,
		});

		expect(needsMemory.decision).toBe("continue");
		expect(needsMemory.memoryPersisted).toBe(false);
		expect(needsMemory.readyForNextPhase).toBe(false);
		expect(needsMemory.remainingCriteria).toContain("security memory persistence");
		expect(needsMemory.nextToolCalls.map((tool) => tool.tool)).toContain("security_memory");
		expect(needsMemory.operatorChoicePrompt.options).toContain("Skip with limitations");

		const complete = buildSecuritySubagentIterationPlan({
			subagent: "attack_surface_analysis",
			phase: "attack_surface_analysis",
			objective: "Map surface for example.com",
			targets: ["example.com"],
			collectedEvidence: [
				"attack surface map covers exposed services, technology/service inventory, entry points, and evidence gaps",
				"handoff includes services, middleware, product/version evidence, HTTP/API entry points, authentication boundaries, and configuration observations",
				"security_memory action=remember stored memory metadata for final handoff, evidence sources, and limitations",
			],
			iteration: 3,
		});

		expect(complete.decision).toBe("complete");
		expect(complete.memoryPersisted).toBe(true);
		expect(complete.readyForNextPhase).toBe(true);
		expect(complete.nextToolCalls).toEqual([]);
		expect(complete.stopReason).toContain("Attack Surface Analysis Subagent has enough evidence");
		expect(complete.memoryActions.join("\n")).toContain("Persist the final Attack Surface Analysis Subagent handoff");
		expect(complete.operatorChoicePrompt.options).toContain("Proceed to next phase");

		const manual = buildSecuritySubagentIterationPlan({
			subagent: "poc_research",
			phase: "vulnerability_scanning",
			objective: "Research PoC references for nginx",
			targets: ["example.com"],
			missingInformation: ["PoC availability notes"],
			toolErrors: ["NVD request timed out", "Exploit-DB mirror unavailable"],
			iteration: 2,
		});

		expect(manual.decision).toBe("manual_intervention");
		expect(manual.manualInterventionPrompt?.options).toContain("Approve alternate method");
		expect(manual.operatorChoicePrompt.options).toContain("Stop phase");
		expect(manual.operatorChoicePrompt.options).toContain("人工建议");
		expect(manual.fallbackActions.join("\n")).toContain("Review tool error");
		expect(manual.memoryActions.join("\n")).toContain("Persist failed attempts");
	});

	it("defines the dedicated security subagents with narrow responsibilities", () => {
		for (const folder of ["asset-discovery", "attack-surface-analysis", "poc-research"]) {
			for (const file of ["index.ts", "memory.ts", "model.ts", "prompt.ts", "tools.ts"]) {
				expect(existsSync(join(process.cwd(), `src/core/subagent/${folder}/${file}`))).toBe(true);
			}
		}
		expect(SECURITY_DEDICATED_SUBAGENTS.map((subagent) => subagent.name)).toEqual([
			"asset_discovery",
			"attack_surface_analysis",
			"poc_research",
		]);
		expect(SECURITY_DEDICATED_SUBAGENTS).toEqual([
			ASSET_DISCOVERY_SUBAGENT,
			ATTACK_SURFACE_ANALYSIS_SUBAGENT,
			POC_RESEARCH_SUBAGENT,
		]);
		expect(ASSET_DISCOVERY_SUBAGENT.memory.handoff).toContain("asset inventory");
		expect(ATTACK_SURFACE_ANALYSIS_SUBAGENT.tools.optionalTools).toContain("security_web_analysis");
		expect(POC_RESEARCH_SUBAGENT.tools.requiredTools).toContain("security_assessment");
		expect(POC_RESEARCH_SUBAGENT.prompt.systemPrompt).toContain("Do not execute exploits");
		expect(ASSET_DISCOVERY_SUBAGENT.tools.toolCalls?.map((tool) => tool.tool)).toEqual([
			"security_scope_status",
			"security_memory",
			"security_research",
			"api_client",
			"security_report",
		]);
		expect(ASSET_DISCOVERY_SUBAGENT.tools.toolCalls?.map((tool) => tool.tool)).not.toContain(
			"security_network_discovery",
		);
		expect(ASSET_DISCOVERY_SUBAGENT.tools.requiredTools).toEqual(["security_scope_status", "security_memory"]);
		expect(
			ASSET_DISCOVERY_SUBAGENT.tools.externalToolCalls?.find(
				(tool) => tool.method === "DNS and certificate transparency enumeration",
			)?.required,
		).toBe(true);
		expect(
			ASSET_DISCOVERY_SUBAGENT.tools.externalToolCalls?.find(
				(tool) => tool.method === "Internet exposure index search",
			)?.expectedOutput,
		).toContain("indexed hosts");
		expect(ASSET_DISCOVERY_SUBAGENT.prompt.systemPrompt).toContain(
			"externalToolCalls as the primary asset collection plan",
		);
		expect(ASSET_DISCOVERY_SUBAGENT.prompt.systemPrompt).toContain(
			"Use security_research for passive public exploration",
		);
		expect(SECURITY_DEDICATED_SUBAGENTS.find((subagent) => subagent.name === "poc_research")?.mission).toContain(
			"services, middleware, products, versions, CVEs",
		);
		expect(
			SECURITY_DEDICATED_SUBAGENTS.find((subagent) => subagent.name === "asset_discovery")?.boundaries,
		).toContain("Do not analyze exploitability or PoC viability.");
	});

	it("defines actionable asset discovery built-in tool calls for every referenced tool", () => {
		const registeredToolNames = new Set(createSecuritySubagentTools().map((tool) => tool.name));
		const calls = ASSET_DISCOVERY_SUBAGENT.tools.toolCalls ?? [];
		const externalCalls = ASSET_DISCOVERY_SUBAGENT.tools.externalToolCalls ?? [];

		expect(calls.length).toBeGreaterThan(0);
		expect(externalCalls.length).toBeGreaterThan(calls.length);
		expect(new Set(calls.map((call) => call.tool))).toEqual(
			new Set(ASSET_DISCOVERY_SUBAGENT.tools.requiredTools.concat(ASSET_DISCOVERY_SUBAGENT.tools.optionalTools)),
		);
		expect(calls.filter((call) => call.required).map((call) => call.tool)).toEqual(
			ASSET_DISCOVERY_SUBAGENT.tools.requiredTools,
		);
		expect(calls.filter((call) => !call.required).map((call) => call.tool)).toEqual(
			ASSET_DISCOVERY_SUBAGENT.tools.optionalTools,
		);
		for (const call of calls) {
			expect(registeredToolNames.has(call.tool)).toBe(true);
			expect(call.label.trim()).not.toBe("");
			expect(call.description.trim()).not.toBe("");
			expect(call.promptSnippet.trim()).not.toBe("");
			expect(call.promptGuidelines.length).toBeGreaterThan(0);
			expect(call.inputsNeeded.length).toBeGreaterThan(0);
			expect(call.expectedOutput.trim()).not.toBe("");
			expect(call.useWhen.trim()).not.toBe("");
			expect(call.safetyConstraints.join("\n")).toContain("authorization scope");
			expect(call.nextStepUse.trim()).not.toBe("");
			for (const parameter of call.parameters) {
				expect(parameter.name.trim()).not.toBe("");
				expect(parameter.description.trim()).not.toBe("");
				expect(parameter.source.trim()).not.toBe("");
			}
		}

		const scope = calls.find((call) => call.tool === "security_scope_status");
		expect(scope?.required).toBe(true);
		expect(scope?.useWhen).toContain("Always at the start");
		expect(scope?.nextStepUse).toContain("Gate all subsequent");

		const memory = calls.find((call) => call.tool === "security_memory");
		expect(memory?.parameters.map((parameter) => parameter.name)).toEqual(["action", "query", "content"]);
		expect(memory?.promptGuidelines.join("\n")).toContain("Store the final asset inventory");

		const research = calls.find((call) => call.tool === "security_research");
		expect(research?.parameters.map((parameter) => parameter.name)).toEqual([
			"query",
			"target_url",
			"include_search",
			"include_api",
		]);
		expect(research?.description).toContain("passive public information exploration");
		expect(research?.expectedOutput).toContain("candidate assets");

		const api = calls.find((call) => call.tool === "api_client");
		expect(api?.promptGuidelines.join("\n")).toContain("preset=dns_resolve");
		expect(api?.promptGuidelines.join("\n")).toContain("after security_research");
		expect(api?.expectedOutput).toContain("DNS answers");

		const report = calls.find((call) => call.tool === "security_report");
		expect(report?.required).toBe(false);
		expect(report?.expectedOutput).toContain("Markdown/JSON");
	});

	it("defines actionable asset discovery external tool calls for every external method", () => {
		const calls = ASSET_DISCOVERY_SUBAGENT.tools.externalToolCalls ?? [];
		const expectedMethods = [
			"Customer-provided asset inventory",
			"Domain ownership and registration lookup",
			"DNS and certificate transparency enumeration",
			"Passive subdomain enumeration",
			"Attack surface relationship mapping",
			"DNS resolution validation",
			"HTTP service probing",
			"Technology fingerprinting",
			"Path and content discovery",
			"Virtual host discovery",
			"Robots and sitemap discovery",
			"Internet exposure index search",
			"Public code and documentation search",
			"Cloud asset inventory import",
			"Reverse IP and virtual-host correlation",
			"Nmap",
		];

		expect(calls.map((call) => call.method)).toEqual(expectedMethods);
		expect(ASSET_DISCOVERY_SUBAGENT.tools.externalMethods).toEqual(expectedMethods);
		for (const call of calls) {
			expect([
				"user_supplied",
				"passive_osint",
				"external_platform",
				"authorized_terminal",
				"cloud_inventory",
			]).toContain(call.category);
			expect(call.inputsNeeded.length).toBeGreaterThan(0);
			expect(call.expectedOutput.trim()).not.toBe("");
			expect(call.useWhen.trim()).not.toBe("");
			expect(call.prompt.trim()).not.toBe("");
			expect(call.safetyConstraints.join("\n")).toContain("authorization scope");
		}

		const requiredMethods = calls.filter((call) => call.required).map((call) => call.method);
		expect(requiredMethods).toEqual([
			"Customer-provided asset inventory",
			"DNS and certificate transparency enumeration",
		]);
		expect(calls.find((call) => call.method === "Passive subdomain enumeration")?.category).toBe(
			"authorized_terminal",
		);
		expect(calls.find((call) => call.method === "Nmap")?.category).toBe("authorized_terminal");
		expect(calls.find((call) => call.method === "Nmap")?.inputsNeeded.join("\n")).toContain("1-65535");
		expect(calls.find((call) => call.method === "Nmap")?.expectedOutput).toContain("full TCP 1-65535");
		expect(calls.find((call) => call.method === "Nmap")?.expectedOutput).toContain("open ports");
		expect(calls.find((call) => call.method === "Nmap")?.prompt).toContain("-p 1-65535");
		expect(calls.find((call) => call.method === "Nmap")?.prompt).toContain("action=start");
		expect(calls.find((call) => call.method === "Nmap")?.safetyConstraints.join("\n")).toContain(
			"default asset-discovery Nmap port scope",
		);
		expect(calls.find((call) => call.method === "Nmap")?.safetyConstraints.join("\n")).toContain(
			"do not assume 120s is enough",
		);
		expect(calls.find((call) => call.method === "Nmap")?.safetyConstraints.join("\n")).toContain("NSE scripts");
		expect(calls.find((call) => call.method === "Technology fingerprinting")?.prompt).toContain("WhatWeb");
		expect(calls.find((call) => call.method === "Path and content discovery")?.prompt).toContain("FFUF");
		expect(
			calls.find((call) => call.method === "Path and content discovery")?.safetyConstraints.join("\n"),
		).toContain("path brute forcing");
		expect(calls.find((call) => call.method === "Virtual host discovery")?.expectedOutput).toContain(
			"candidate virtual hosts",
		);
		expect(calls.find((call) => call.method === "Robots and sitemap discovery")?.prompt).toContain("robots.txt");
		expect(calls.find((call) => call.method === "Attack surface relationship mapping")?.prompt).toContain(
			"Prefer passive",
		);
		expect(calls.find((call) => call.method === "Internet exposure index search")?.prompt).toContain(
			"Do not expose API keys",
		);
		expect(calls.find((call) => call.method === "Public code and documentation search")?.prompt).toContain(
			"Do not collect",
		);
		expect(calls.find((call) => call.method === "Cloud asset inventory import")?.category).toBe("cloud_inventory");
		expect(calls.find((call) => call.method === "Reverse IP and virtual-host correlation")?.prompt).toContain(
			"Do not treat co-hosted domains as in scope",
		);
	});

	it("defines external-method-first attack surface analysis tool plans", () => {
		const registeredToolNames = new Set(createSecuritySubagentTools().map((tool) => tool.name));
		const builtInCalls = ATTACK_SURFACE_ANALYSIS_SUBAGENT.tools.toolCalls ?? [];
		const externalCalls = ATTACK_SURFACE_ANALYSIS_SUBAGENT.tools.externalToolCalls ?? [];

		expect(new Set(builtInCalls.map((call) => call.tool))).toEqual(
			new Set(
				ATTACK_SURFACE_ANALYSIS_SUBAGENT.tools.requiredTools.concat(
					ATTACK_SURFACE_ANALYSIS_SUBAGENT.tools.optionalTools,
				),
			),
		);
		expect(builtInCalls.map((call) => call.tool)).toEqual([
			"security_memory",
			"security_web_analysis",
			"security_crawl",
			"security_external_tool_runner",
			"api_client",
			"security_report",
		]);
		expect(externalCalls.length).toBeGreaterThan(builtInCalls.length);
		for (const call of builtInCalls) {
			expect(registeredToolNames.has(call.tool)).toBe(true);
			expect(call.promptGuidelines.length).toBeGreaterThan(0);
			expect(call.inputsNeeded.length).toBeGreaterThan(0);
			expect(call.expectedOutput.trim()).not.toBe("");
			expect(call.useWhen.trim()).not.toBe("");
			expect(call.safetyConstraints.join("\n")).toContain("asset discovery handoff");
			expect(call.nextStepUse.trim()).not.toBe("");
		}
		for (const call of externalCalls) {
			expect(call.inputsNeeded.length).toBeGreaterThan(0);
			expect(call.expectedOutput.trim()).not.toBe("");
			expect(call.useWhen.trim()).not.toBe("");
			expect(call.prompt.trim()).not.toBe("");
			expect(call.safetyConstraints.join("\n")).toContain("authorized targets");
		}

		expect(ATTACK_SURFACE_ANALYSIS_SUBAGENT.tools.externalMethods).toEqual(externalCalls.map((call) => call.method));
		expect(externalCalls.map((call) => call.method)).toEqual([
			"Service Discovery",
			"HTTP Surface Discovery",
			"Technology Fingerprinting",
			"Visual Surface Analysis",
			"Route Discovery",
			"Web Crawling",
			"JavaScript Analysis",
			"API & Metadata Discovery",
		]);
		expect(externalCalls.filter((call) => call.required).map((call) => call.method)).toEqual([
			"Service Discovery",
			"HTTP Surface Discovery",
			"Technology Fingerprinting",
			"JavaScript Analysis",
			"API & Metadata Discovery",
		]);
		expect(externalCalls.find((call) => call.method === "Service Discovery")?.expectedOutput).toContain("open ports");
		expect(externalCalls.find((call) => call.method === "Service Discovery")?.useWhen).toContain("Nmap");
		expect(externalCalls.find((call) => call.method === "Technology Fingerprinting")?.prompt).toContain("Wappalyzer");
		expect(externalCalls.find((call) => call.method === "Route Discovery")?.prompt).toContain("bounded rate");
		expect(externalCalls.find((call) => call.method === "Route Discovery")?.prompt).toContain("Gobuster");
		expect(externalCalls.find((call) => call.method === "API & Metadata Discovery")?.prompt).toContain(
			"explicit approval",
		);
		expect(ATTACK_SURFACE_ANALYSIS_SUBAGENT.prompt.systemPrompt).toContain(
			"externalToolCalls as the primary execution guidance",
		);
		expect(ATTACK_SURFACE_ANALYSIS_SUBAGENT.prompt.systemPrompt).toContain("security_external_tool_runner");
	});

	it("defines external-source-first PoC research tool plans", () => {
		const registeredToolNames = new Set(createSecuritySubagentTools().map((tool) => tool.name));
		const builtInCalls = POC_RESEARCH_SUBAGENT.tools.toolCalls ?? [];
		const externalCalls = POC_RESEARCH_SUBAGENT.tools.externalToolCalls ?? [];

		expect(new Set(builtInCalls.map((call) => call.tool))).toEqual(
			new Set(POC_RESEARCH_SUBAGENT.tools.requiredTools.concat(POC_RESEARCH_SUBAGENT.tools.optionalTools)),
		);
		expect(builtInCalls.map((call) => call.tool)).toEqual([
			"security_scope_status",
			"security_memory",
			"api_client",
			"security_research",
			"security_terminal_session",
			"security_assessment",
			"security_report",
		]);
		expect(externalCalls.length).toBeGreaterThan(builtInCalls.length);
		for (const call of builtInCalls) {
			expect(registeredToolNames.has(call.tool)).toBe(true);
			expect(call.promptGuidelines.length).toBeGreaterThan(0);
			expect(call.inputsNeeded.length).toBeGreaterThan(0);
			expect(call.expectedOutput.trim()).not.toBe("");
			expect(call.useWhen.trim()).not.toBe("");
			expect(call.safetyConstraints.join("\n")).toContain("do not execute exploits");
			expect(call.nextStepUse.trim()).not.toBe("");
		}
		for (const call of externalCalls) {
			expect(call.inputsNeeded.length).toBeGreaterThan(0);
			expect(call.expectedOutput.trim()).not.toBe("");
			expect(call.useWhen.trim()).not.toBe("");
			expect(call.prompt.trim()).not.toBe("");
			expect(call.safetyConstraints.join("\n")).toContain("PoC availability");
		}

		expect(POC_RESEARCH_SUBAGENT.tools.externalMethods).toEqual(externalCalls.map((call) => call.method));
		expect(externalCalls.map((call) => call.method)).toEqual([
			"NVD",
			"CVE.org",
			"MITRE ATT&CK",
			"GitHub Security Advisories",
			"Exploit and public PoC references",
			"Public advisory and writeup sources",
			"Network and application scanner import",
			"Supply-chain and code scanner import",
			"Vendor advisories",
		]);
		expect(externalCalls.filter((call) => call.required).map((call) => call.method)).toEqual([
			"NVD",
			"CVE.org",
			"MITRE ATT&CK",
			"GitHub Security Advisories",
			"Vendor advisories",
		]);
		expect(externalCalls.find((call) => call.method === "Exploit and public PoC references")?.prompt).toContain(
			"do not execute",
		);
		expect(externalCalls.find((call) => call.method === "Network and application scanner import")?.prompt).toContain(
			"security_scope_status",
		);
		expect(
			externalCalls.find((call) => call.method === "Supply-chain and code scanner import")?.expectedOutput,
		).toContain("package vulnerabilities");
		expect(externalCalls.find((call) => call.method === "Vendor advisories")?.useWhen).toContain(
			"highest-confidence",
		);
		expect(POC_RESEARCH_SUBAGENT.prompt.systemPrompt).toContain("externalToolCalls as the primary source plan");
		expect(POC_RESEARCH_SUBAGENT.prompt.systemPrompt).toContain("technology fingerprints");
		expect(POC_RESEARCH_SUBAGENT.prompt.systemPrompt).toContain("do not use security_explore as a shortcut");
	});

	it("keeps authorization checks in active phase execution plans when scope is not confirmed", () => {
		const plan = buildSecurityStepExecutionPlan({
			phase: "asset_discovery",
			objective: "Discover assets for example.com",
			targets: ["example.com"],
			authorizationConfirmed: false,
		});

		expect(plan.selectedToolCalls[0]?.tool).toBe("security_user_approval");
		expect(plan.selectedToolCalls[1]?.tool).toBe("security_delegate_subagent");
		expect(plan.selectedToolCalls[2]?.tool).toBe("security_subagent_iteration_plan");
		expect(plan.selectedToolCalls[3]?.tool).toBe("security_scope_status");
		expect(plan.subagentDispatch?.subagent).toBe("asset_discovery");
		expect(plan.safetyChecks.join("\n")).toContain("active authorization");
		expect(plan.missingInformation).toContain("test window");
	});

	it("uses interactive selectable approval for gated security consent", async () => {
		const approvalTool = createSecuritySubagentTools().find((tool) => tool.name === "security_user_approval");
		if (!approvalTool) throw new Error("security_user_approval tool not found");
		let capturedTitle = "";
		let capturedOptions: string[] = [];
		const result = await approvalTool.execute(
			"call-1",
			{
				title: "Approve asset discovery",
				message: "Target: example.com\nAction: asset discovery",
				request_type: "phase_start",
				approve_label: "Approve",
				reject_label: "Reject",
			},
			undefined,
			undefined,
			{
				hasUI: true,
				signal: undefined,
				ui: {
					select: async (title: string, options: string[]) => {
						capturedTitle = title;
						capturedOptions = options;
						return options[0];
					},
				},
			} as never,
		);

		expect(result.content[0]?.type === "text" ? result.content[0].text : "").toContain("approved");
		expect(capturedTitle).toContain("Target: example.com");
		expect(capturedOptions).toEqual([
			"Approve",
			"Approve all next-phase requests this session",
			"Reject",
			"人工建议",
		]);
		expect(JSON.stringify(result.details)).toContain('"approved":true');
		expect(JSON.stringify(result.details)).toContain("Up/Down");
	});

	it("collects manual suggestions from approval choices for replanning", async () => {
		const approvalTool = createSecuritySubagentTools().find((tool) => tool.name === "security_user_approval");
		if (!approvalTool) throw new Error("security_user_approval tool not found");
		let capturedOptions: string[] = [];
		const result = await approvalTool.execute(
			"call-1",
			{
				title: "Choose next action",
				message: "Need operator guidance",
				request_type: "phase_start",
				options: ["Continue collecting", "Skip with limitations"],
			},
			undefined,
			undefined,
			{
				hasUI: true,
				signal: undefined,
				ui: {
					select: async (_title: string, options: string[]) => {
						capturedOptions = options;
						return "人工建议";
					},
					input: async () => "Use imported nmap XML and narrow to app subnet",
				},
			} as never,
		);

		expect(capturedOptions).toEqual(["Continue collecting", "Skip with limitations", "人工建议"]);
		expect(JSON.stringify(result.details)).toContain('"ui":"manual_input"');
		expect(JSON.stringify(result.details)).toContain('"replanRequired":true');
		expect(JSON.stringify(result.details)).toContain("Use imported nmap XML");
		expect(JSON.stringify(result.details)).toContain("Tab");
	});

	it("can remember approve-all for next-phase requests in the current tool instance", async () => {
		const approvalTool = createSecuritySubagentTools().find((tool) => tool.name === "security_user_approval");
		if (!approvalTool) throw new Error("security_user_approval tool not found");
		const ctx = {
			hasUI: true,
			signal: undefined,
			ui: {
				select: async (_title: string, options: string[]) => options[1],
			},
		} as never;

		const first = await approvalTool.execute(
			"call-1",
			{
				title: "Approve attack surface analysis",
				message: "Target: example.com",
				request_type: "phase_start",
			},
			undefined,
			undefined,
			ctx,
		);
		const second = await approvalTool.execute(
			"call-2",
			{
				title: "Approve vulnerability scanning",
				message: "Target: example.com",
				request_type: "phase_start",
			},
			undefined,
			undefined,
			ctx,
		);

		expect(JSON.stringify(first.details)).toContain("next_phase_requests");
		expect(JSON.stringify(second.details)).toContain('"ui":"remembered"');
		expect(JSON.stringify(second.details)).toContain('"approved":true');
	});

	it("correlates collected evidence into defensive vulnerability findings", () => {
		const result = assessVulnerabilities({
			scope: ["https://example.com"],
			discoveredHosts: [
				{
					host: "example.com",
					openServices: [{ port: 3389, service: "rdp", status: "open" }],
					openCount: 1,
				},
			],
			headerChecks: [
				{
					url: "https://example.com",
					status: 200,
					headers: {
						present: ["X-Content-Type-Options"],
						missing: ["Strict-Transport-Security", "Content-Security-Policy"],
					},
					score: 17,
				},
			],
			vulnerabilities: [
				createUnifiedVulnerability({
					vulnId: "CVE-2099-0003",
					source: "nvd",
					title: "Example critical vulnerability",
					description: "A defensive test vulnerability record with public references.",
					severity: "critical",
					cvssScore: 9.8,
					references: ["https://example.com/cve"],
					affectedSoftware: [{ vendor: "example", product: "service", versions: ["1.0.0"] }],
				}),
			],
		});

		expect(result.summary.totalFindings).toBe(3);
		expect(result.summary.highestSeverity).toBe("critical");
		expect(result.summary.bySeverity.high).toBe(1);
		expect(result.findings[0]?.title).toBe("Example critical vulnerability");
		expect(result.findings.map((finding) => finding.category)).toContain("web_configuration");
		expect(result.limitations.join("\n")).toContain("provided evidence");
	});

	it("analyzes supplied detection events without live monitoring", () => {
		const result = analyzeDetections({
			events: [
				...Array.from({ length: 5 }, (_, index) => ({
					timestamp: `2026-06-16T00:0${index}:00.000Z`,
					source: "auth.log",
					eventType: "auth",
					message: "failed password for analyst",
					srcIp: "198.51.100.10",
					username: "analyst",
				})),
				...Array.from({ length: 5 }, (_, index) => ({
					source: "firewall",
					eventType: "connection",
					message: "allowed tcp connection",
					srcIp: "198.51.100.20",
					destIp: "203.0.113.10",
					destPort: 20 + index,
				})),
				{
					source: "edr",
					eventType: "process",
					message: "powershell -enc suspicious encodedcommand observed",
				},
			],
		});

		expect(result.summary.totalEvents).toBe(11);
		expect(result.summary.totalFindings).toBe(3);
		expect(result.summary.bySeverity.high).toBe(1);
		expect(result.findings.map((finding) => finding.mitreTechnique)).toContain("T1110");
		expect(result.findings.map((finding) => finding.category)).toContain("network_reconnaissance");
		expect(result.limitations.join("\n")).toContain("does not monitor live traffic");
	});

	it("runs read-only security exploration with injectable research dependencies", async () => {
		const deps: SecurityExploreDeps = {
			vulnerabilityLookup: async (_args) => ({
				mode: "by_query",
				source: "all",
				query: "log4j example.com",
				matchedCount: 1,
				matchedVulns: [
					createUnifiedVulnerability({
						vulnId: "CVE-2021-44228",
						source: "nvd",
						title: "Log4Shell",
						description: "Example defensive test record.",
						severity: "critical",
						references: ["https://example.com/advisory"],
					}),
				],
			}),
			search: async (_args) => ({
				query: "log4j example.com",
				total: 1,
				results: [{ title: "Advisory", url: "https://example.com/advisory", snippet: "Security advisory" }],
			}),
			extract: async (_args) => ({
				url: "https://example.com/",
				title: "Example",
				mode: "structured",
				headings: [{ level: 1, text: "Example" }],
				links: [],
				images: [],
				meta: {},
				robots: "allowed",
			}),
			crawl: async (_args) => ({
				startUrl: "https://example.com/",
				maxDepth: 1,
				pagesCrawled: 1,
				pages: [
					{
						url: "https://example.com/",
						depth: 0,
						title: "Example",
						contentPreview: "Example content",
						contentLength: 15,
						linksFound: 0,
						links: [],
					},
				],
				errors: [],
				partial: false,
			}),
			api: async (_args) => ({
				url: "https://dns.google/resolve?name=example.com&type=A",
				method: "GET",
				statusCode: 200,
				ok: true,
				contentType: "application/json",
				elapsedMs: 1,
				responseHeaders: {},
				data: { Answer: [] },
			}),
		};

		const result = await runSecurityExploration(
			{
				query: "log4j example.com",
				targetUrl: "https://example.com",
				cveId: "CVE-2021-44228",
				includeCrawl: true,
				includeApi: true,
			},
			deps,
		);

		expect(result.mode).toBe("react_explore");
		expect(result.observations.map((observation) => observation.step)).toEqual([
			"vulnerability_lookup",
			"web_search",
			"page_extract",
			"deep_crawl",
			"api_metadata",
		]);
		expect(result.contextPatch.evidenceCount).toBe(5);
		expect(result.contextPatch.focus).toContain("example.com");
		expect(result.recommendedNextSteps.join("\n")).toContain("security_report");
	});

	it("normalizes vulnerability records into a unified schema", () => {
		const vuln = createUnifiedVulnerability({
			vulnId: "CVE-2099-0001",
			source: "nvd",
			title: "Example vulnerability",
			description: "A defensive test vulnerability record.",
			severity: "high",
			cvssScore: 8.1,
			affectedSoftware: [{ vendor: "example", product: "widget", versions: ["1.0.0"] }],
			attackTechniques: [
				{
					techniqueId: "T1190",
					name: "Exploit Public-Facing Application",
					tactic: "initial-access",
					description: "Technique mapping for defensive context.",
					url: "https://attack.mitre.org/techniques/T1190/",
				},
			],
		});

		expect(vuln.source).toBe("nvd");
		expect(buildVulnerabilityEmbeddingText(vuln)).toContain("example widget 1.0.0");
		expect(vulnerabilityToSummary(vuln)).toContain("ATT&CK: T1190");
	});

	it("normalizes NVD vulnerability payloads", () => {
		const vuln = normalizeNvdItem({
			cve: {
				id: "CVE-2099-0002",
				descriptions: [{ lang: "en", value: "Example NVD description" }],
				metrics: {
					cvssMetricV31: [{ baseSeverity: "HIGH", cvssData: { baseScore: 8.8, vectorString: "CVSS:3.1/X" } }],
				},
				configurations: [
					{
						nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:example:widget:1.2.3:*:*:*:*:*:*:*" }] }],
					},
				],
				references: [{ url: "https://example.com/advisory", tags: ["Exploit"], source: "vendor" }],
				weaknesses: [{ description: [{ value: "CWE-79" }] }],
				published: "2099-01-01T00:00:00.000",
				lastModified: "2099-01-02T00:00:00.000",
				vulnStatus: "Analyzed",
			},
		});

		expect(vuln?.source).toBe("nvd");
		expect(vuln?.affectedSoftware[0]?.product).toBe("widget");
		expect(vuln?.exploits[0]?.source).toBe("vendor");
		expect(vuln?.tags).toContain("CWE-79");
	});

	it("normalizes MITRE ATT&CK techniques", () => {
		const vuln = normalizeMitreAttackObject("T1190", {
			type: "attack-pattern",
			name: "Exploit Public-Facing Application",
			description: "Adversaries may exploit public-facing applications.",
			x_mitre_platforms: ["Linux"],
			kill_chain_phases: [{ phase_name: "initial-access" }],
			external_references: [
				{
					source_name: "mitre-attack",
					external_id: "T1190",
					url: "https://attack.mitre.org/techniques/T1190/",
				},
			],
		});

		expect(vuln.source).toBe("mitre_attack");
		expect(vuln.attackTechniques[0]?.techniqueId).toBe("T1190");
		expect(vuln.tags).toContain("initial-access");
	});

	it("normalizes Exploit-DB rows", () => {
		const vuln = normalizeExploitDbRow({
			id: "12345",
			title: "Example exploit reference",
			platform: "linux",
			type: "remote",
			verified: true,
		});

		expect(vuln.vulnId).toBe("EDB-12345");
		expect(vuln.source).toBe("exploit_db");
		expect(vuln.exploits[0]?.verified).toBe(true);
		expect(vuln.references[0]).toContain("exploit-db.com");
	});

	it("blocks active checks outside the authorized scope", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({
			targets: ["example.com"],
			expiresAt: "2099-06-16T01:00:00.000Z",
		});
		const portTool = createSecuritySubagentTools(store).find((tool) => tool.name === "security_port_check");
		if (!portTool) throw new Error("security_port_check tool not found");

		await expect(
			portTool.execute("call-1", { host: "example.org" }, undefined, undefined, undefined as never),
		).rejects.toThrow("Target is not in the active security authorization scope");
	});

	it("returns partial web analysis when fetch fails", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({
			targets: ["example.com"],
			expiresAt: "2099-06-16T01:00:00.000Z",
		});
		const webAnalysisTool = createSecuritySubagentTools(store).find((tool) => tool.name === "security_web_analysis");
		if (!webAnalysisTool) throw new Error("security_web_analysis tool not found");
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
		try {
			const result = await webAnalysisTool.execute(
				"call-1",
				{ url: "https://example.com:9443" },
				undefined,
				undefined,
				undefined as never,
			);
			const details = result.details as {
				partial: boolean;
				headers: unknown;
				page: unknown;
				errors: Array<{ stage: string; message: string }>;
				recommendations: string[];
			};
			expect(details.partial).toBe(true);
			expect(details.headers).toBeNull();
			expect(details.page).toBeNull();
			expect(details.errors.map((error) => error.stage)).toEqual(["headers", "page_extract"]);
			expect(details.errors.map((error) => error.message).join("\n")).toContain("fetch failed");
			expect(details.recommendations.join("\n")).toContain("self-signed");
			expect(details.recommendations.join("\n")).toContain("api_client");
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("returns structured api_client errors instead of throwing on fetch failure", async () => {
		const apiTool = createSecuritySubagentTools().find((tool) => tool.name === "api_client");
		if (!apiTool) throw new Error("api_client tool not found");
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
		try {
			const result = await apiTool.execute(
				"call-1",
				{ url: "https://example.com:9443/robots.txt" },
				undefined,
				undefined,
				undefined as never,
			);
			const details = result.details as { ok: boolean; partial: boolean; error: string; recommendations: string[] };
			expect(details.ok).toBe(false);
			expect(details.partial).toBe(true);
			expect(details.error).toContain("fetch failed");
			expect(details.recommendations.join("\n")).toContain("different scheme");
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("records crawl errors instead of silently returning an empty route map", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({ targets: ["example.com"], expiresAt: "2099-06-16T01:00:00.000Z" });
		const crawlTool = createSecuritySubagentTools(store).find((tool) => tool.name === "security_crawl");
		if (!crawlTool) throw new Error("security_crawl tool not found");
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
		try {
			const result = await crawlTool.execute(
				"call-1",
				{ start_url: "https://example.com:9443" },
				undefined,
				undefined,
				undefined as never,
			);
			const details = result.details as {
				pagesCrawled: number;
				partial: boolean;
				errors: Array<{ url: string; message: string }>;
			};
			expect(details.pagesCrawled).toBe(0);
			expect(details.partial).toBe(true);
			expect(details.errors[0]?.url).toBe("https://example.com:9443/");
			expect(details.errors[0]?.message).toContain("fetch failed");
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("requires authorization for security research target URLs", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({ targets: ["example.com"], expiresAt: "2099-06-16T01:00:00.000Z" });
		const researchTool = createSecuritySubagentTools(store).find((tool) => tool.name === "security_research");
		if (!researchTool) throw new Error("security_research tool not found");

		await expect(
			researchTool.execute(
				"call-1",
				{ query: "admin portal", target_url: "https://example.org" },
				undefined,
				undefined,
				undefined as never,
			),
		).rejects.toThrow("Target is not in the active security authorization scope");
	});

	it("returns partial results from legacy read-only web tools when fetch fails", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({ targets: ["example.com"], expiresAt: "2099-06-16T01:00:00.000Z" });
		const tools = createSecuritySubagentTools(store);
		const smartSearch = tools.find((tool) => tool.name === "smart_search");
		const pageExtract = tools.find((tool) => tool.name === "page_extract");
		const deepCrawl = tools.find((tool) => tool.name === "deep_crawl");
		const headerCheck = tools.find((tool) => tool.name === "security_header_check");
		if (!smartSearch) throw new Error("smart_search tool not found");
		if (!pageExtract) throw new Error("page_extract tool not found");
		if (!deepCrawl) throw new Error("deep_crawl tool not found");
		if (!headerCheck) throw new Error("security_header_check tool not found");

		const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("fetch failed"));
		try {
			const searchResult = await smartSearch.execute(
				"call-1",
				{ query: "example advisory" },
				undefined,
				undefined,
				undefined as never,
			);
			const pageResult = await pageExtract.execute(
				"call-2",
				{ url: "https://example.com:9443" },
				undefined,
				undefined,
				undefined as never,
			);
			const crawlResult = await deepCrawl.execute(
				"call-3",
				{ start_url: "https://example.com:9443" },
				undefined,
				undefined,
				undefined as never,
			);
			const headerResult = await headerCheck.execute(
				"call-4",
				{ url: "https://example.com:9443" },
				undefined,
				undefined,
				undefined as never,
			);
			for (const result of [searchResult, pageResult, crawlResult, headerResult]) {
				const details = result.details as { partial: boolean; error?: string; errors?: Array<{ message: string }> };
				expect(details.partial).toBe(true);
				expect(details.error ?? details.errors?.[0]?.message).toContain("fetch failed");
			}
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("requires explicit or prior-result ports for TCP checks", async () => {
		await expect(checkTcpPorts({ host: "localhost", ports: [] })).rejects.toThrow(
			"At least one TCP port, port profile, or port range is required",
		);
	});

	it("builds dedicated small-model prompts for bounded payload candidates", () => {
		const prompt = buildSecurityPayloadPrompt({
			task: "scanner_command",
			objective: "Check HTTP security headers safely",
			targets: ["example.com"],
			authorizedActions: ["manual_validation"],
			constraints: ["no writes", "low rate"],
		});

		expect(prompt.modelConfig.provider).toBe("security-payload-local");
		expect(prompt.modelConfig.fallback.mode).toBe("current_main_model");
		expect(prompt.systemPrompt).toContain("Do not include persistence");
		expect(prompt.userPrompt).toContain("example.com");
		expect(prompt.fallbackPrompt).toContain("Main model fallback instruction");
		expect(prompt.reviewRequirements.join("\n")).toContain("Main model must verify active user authorization");
	});

	it("expands bounded IPv4 CIDR discovery targets", () => {
		expect(expandDiscoveryTargets(["192.0.2.0/30"], 10)).toEqual(["192.0.2.1", "192.0.2.2"]);
		expect(expandDiscoveryTargets(["https://example.com", "192.0.2.10"], 10)).toEqual(["example.com", "192.0.2.10"]);
		expect(() => expandDiscoveryTargets(["192.0.2.0/23"], 10)).toThrow("limited to IPv4 /24 through /32");
	});

	it("blocks network discovery outside the authorized scope before scanning", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({
			targets: ["192.0.2.1"],
			now: new Date("2026-06-16T00:00:00.000Z"),
		});
		const discoveryTool = createSecuritySubagentTools(store).find(
			(tool) => tool.name === "security_network_discovery",
		);
		if (!discoveryTool) throw new Error("security_network_discovery tool not found");

		await expect(
			discoveryTool.execute(
				"call-1",
				{ targets: ["192.0.2.0/30"], ports: [80], max_hosts: 2 },
				undefined,
				undefined,
				undefined as never,
			),
		).rejects.toThrow("Target is not in the active security authorization scope");
	});

	it("blocks terminal sessions without active authorization", async () => {
		const terminalTool = createSecuritySubagentTools(
			createSecurityAuthorizationStore(),
			createSecurityTerminalManager(),
		).find((tool) => tool.name === "security_terminal_session");
		if (!terminalTool) throw new Error("security_terminal_session tool not found");

		await expect(
			terminalTool.execute("call-1", { action: "list" }, undefined, undefined, undefined as never),
		).rejects.toThrow("No active security authorization scope");
	});

	it("does not block security terminal commands by tool name", () => {
		const terminal = createSecurityTerminalManager();

		expect(terminal.validateCommand("sqlmap --version")).toBeUndefined();
		expect(terminal.validateCommand("nmap -sV 127.0.0.1")).toBeUndefined();
		expect(terminal.validateCommand("")).toBe("command is required.");
	});

	it("runs a bounded authorized terminal session", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({ targets: ["localhost"], expiresAt: "2099-06-16T01:00:00.000Z" });
		const terminalTool = createSecuritySubagentTools(store, createSecurityTerminalManager()).find(
			(tool) => tool.name === "security_terminal_session",
		);
		if (!terminalTool) throw new Error("security_terminal_session tool not found");

		const opened = await terminalTool.execute("call-1", { action: "open" }, undefined, undefined, undefined as never);
		const details = opened.details as { sessionId: string };
		try {
			const executed = await terminalTool.execute(
				"call-2",
				{
					action: "exec",
					session_id: details.sessionId,
					command: "echo myagent-security-terminal",
					timeout_sec: 5,
				},
				undefined,
				undefined,
				undefined as never,
			);
			expect(JSON.stringify(executed.details)).toContain("myagent-security-terminal");
		} finally {
			await terminalTool.execute(
				"call-3",
				{ action: "close", session_id: details.sessionId },
				undefined,
				undefined,
				undefined as never,
			);
		}
	});

	it("starts long-running terminal commands asynchronously for later reads", async () => {
		const store = createSecurityAuthorizationStore();
		store.authorize({ targets: ["localhost"], expiresAt: "2099-06-16T01:00:00.000Z" });
		const terminalTool = createSecuritySubagentTools(store, createSecurityTerminalManager()).find(
			(tool) => tool.name === "security_terminal_session",
		);
		if (!terminalTool) throw new Error("security_terminal_session tool not found");

		const opened = await terminalTool.execute("call-1", { action: "open" }, undefined, undefined, undefined as never);
		const details = opened.details as { sessionId: string };
		try {
			const started = await terminalTool.execute(
				"call-2",
				{
					action: "start",
					session_id: details.sessionId,
					command: "echo myagent-async-terminal",
				},
				undefined,
				undefined,
				undefined as never,
			);
			expect(JSON.stringify(started.details)).toContain('"action":"start"');
			await new Promise((resolve) => setTimeout(resolve, 150));
			const read = await terminalTool.execute(
				"call-3",
				{ action: "read", session_id: details.sessionId },
				undefined,
				undefined,
				undefined as never,
			);
			expect(JSON.stringify(read.details)).toContain("myagent-async-terminal");
		} finally {
			await terminalTool.execute(
				"call-4",
				{ action: "close", session_id: details.sessionId },
				undefined,
				undefined,
				undefined as never,
			);
		}
	});

	it("assembles deterministic security reports", () => {
		const report = assembleSecurityReport({
			title: "Example Assessment",
			scope: ["example.com"],
			methodology: ["Read-only research"],
			generatedAt: new Date("2026-06-16T00:00:00.000Z"),
			findings: [
				{
					title: "Missing security headers",
					severity: "medium",
					asset: "https://example.com",
					evidence: "Content-Security-Policy header was not observed.",
					impact: "Browser-side attacks may be easier to execute.",
					remediation: "Add a restrictive Content-Security-Policy header.",
					references: ["https://developer.mozilla.org/"],
				},
			],
		});

		expect(report.summary.bySeverity.medium).toBe(1);
		expect(report.markdown).toContain("# Example Assessment");
		expect(report.markdown).toContain("### Missing security headers");
	});

	it("saves security reports under reports and records a memory summary", async () => {
		const tempDir = mkdtempSync(join(tmpdir(), "pi-security-report-"));
		try {
			const memory = createSecurityMemoryStore();
			const reportTool = createSecuritySubagentTools(undefined, undefined, memory).find(
				(tool) => tool.name === "security_report",
			);
			if (!reportTool) throw new Error("security_report tool not found");

			const result = await reportTool.execute(
				"call-1",
				{
					title: "Saved Assessment",
					scope: ["example.com"],
					findings: [{ title: "Open service", severity: "low", asset: "example.com" }],
					save_to_reports: true,
				},
				undefined,
				undefined,
				{ cwd: tempDir } as never,
			);

			const saved = (result.details as { saved?: { markdownPath: string; jsonPath: string } }).saved;
			expect(saved?.markdownPath).toContain(join(tempDir, "reports"));
			expect(saved?.jsonPath).toContain(join(tempDir, "reports"));
			expect(existsSync(saved?.markdownPath ?? "")).toBe(true);
			expect(memory.recall({ query: "Saved Assessment example.com", limit: 1 })[0]?.content).toContain(
				"Security report generated",
			);
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("loads the security subagent as a built-in extension", async () => {
		const tempDir = mkdtempSync(join(tmpdir(), "pi-security-subagent-"));
		try {
			const services = await createAgentSessionServices({
				cwd: tempDir,
				agentDir: tempDir,
				resourceLoaderOptions: {
					noSkills: true,
					noPromptTemplates: true,
					noThemes: true,
					noContextFiles: true,
				},
			});
			const hasSecurityExtension = services.resourceLoader
				.getExtensions()
				.extensions.some((extension) => extension.path === "<inline:1>");
			expect(hasSecurityExtension).toBe(true);
			const securityExtension = services.resourceLoader
				.getExtensions()
				.extensions.find((extension) => extension.path === "<inline:1>");
			expect([...(securityExtension?.tools.keys() ?? [])]).toEqual([
				"security_authorize_scope",
				"security_user_approval",
				"security_scope_status",
				"security_memory",
				"security_workflow_plan",
				"security_delegate_subagent",
				"security_subagent_iteration_plan",
				"security_step_execution_plan",
				"security_research",
				"security_web_analysis",
				"security_explore",
				"smart_search",
				"page_extract",
				"security_crawl",
				"deep_crawl",
				"api_client",
				"vuln_db_query",
				"security_port_check",
				"security_network_discovery",
				"security_header_check",
				"security_external_tool_runner",
				"security_terminal_session",
				"security_payload_model_prompt",
				"security_detection_analysis",
				"security_assessment",
				"security_vulnerability_assessment",
				"security_report",
			]);
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
