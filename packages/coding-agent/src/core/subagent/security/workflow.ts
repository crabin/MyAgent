import { classifySecurityIntent, type SecurityIntentDecision } from "./intent-router.ts";
import {
	getSecurityDedicatedSubagentDefinition,
	SECURITY_DEDICATED_SUBAGENTS,
	type SecurityDedicatedSubagentDefinition,
	type SecurityDedicatedSubagentName,
} from "./subagents.ts";

export type SecurityAgentMode = "react" | "plan_execute" | "multi_agent_coordination";

export interface SecurityWorkflowInput {
	objective: string;
	targets?: string[];
	authorizationConfirmed?: boolean;
	includeExploration?: boolean;
	includeActiveValidation?: boolean;
	includeReport?: boolean;
	complexity?: "simple" | "complex";
}

export type SecurityWorkflowPhase = SecurityWorkflowStep["phase"];

export interface SecurityStepToolCallPlan {
	tool: string;
	purpose: string;
	required: boolean;
	inputsNeeded: string[];
	expectedOutput: string;
	useWhen: string;
}

export interface SecurityExternalToolPrompt {
	tool: string;
	prompt: string;
	useWhen: string;
	safetyConstraints: string[];
}

export interface SecurityApprovalPrompt {
	title: string;
	message: string;
	options: string[];
	defaultOption: string;
	requiredBefore: "authorization_scope" | "phase_start" | "scope_expansion" | "dangerous_action";
}

const MANUAL_SUGGESTION_OPTION = "人工建议";

export interface SecurityStepExecutionPlanInput {
	phase: SecurityWorkflowPhase;
	objective: string;
	targets?: string[];
	authorizationConfirmed?: boolean;
	priorResults?: string[];
	missingInformation?: string[];
}

export interface SecuritySubagentDelegationInput {
	subagent: SecurityDedicatedSubagentName;
	phase: SecurityWorkflowPhase;
	objective: string;
	targets?: string[];
	priorResults?: string[];
	missingInformation?: string[];
}

export type SecuritySubagentIterationDecision = "continue" | "complete" | "manual_intervention";

export interface SecuritySubagentIterationPlanInput {
	subagent: SecurityDedicatedSubagentName;
	phase: SecurityWorkflowPhase;
	objective: string;
	targets?: string[];
	iteration?: number;
	priorResults?: string[];
	collectedEvidence?: string[];
	missingInformation?: string[];
	toolErrors?: string[];
	completedObjectives?: string[];
	maxIterations?: number;
}

export interface SecuritySubagentIterationPlan {
	subagent: SecurityDedicatedSubagentName;
	displayName: string;
	phase: SecurityWorkflowPhase;
	iteration: number;
	maxIterations: number;
	decision: SecuritySubagentIterationDecision;
	objective: string;
	targets: string[];
	completionCriteria: string[];
	achievedCriteria: string[];
	remainingCriteria: string[];
	memoryPersisted: boolean;
	readyForNextPhase: boolean;
	nextToolCalls: SecurityStepToolCallPlan[];
	nextExternalMethods: SecurityExternalToolPrompt[];
	fallbackActions: string[];
	operatorChoicePrompt: SecurityApprovalPrompt;
	manualInterventionPrompt: SecurityApprovalPrompt | null;
	memoryActions: string[];
	stopReason: string | null;
	replanInputsForNextRound: string[];
}

export interface SecuritySubagentDelegation {
	subagent: SecurityDedicatedSubagentName;
	displayName: string;
	role: SecurityDedicatedSubagentDefinition["model"]["role"];
	phase: SecurityWorkflowPhase;
	objective: string;
	targets: string[];
	systemPrompt: string;
	handoffPrompt: string;
	mission: string;
	focus: string[];
	requiredInputs: string[];
	produces: string[];
	boundaries: string[];
	memory: SecurityDedicatedSubagentDefinition["memory"];
	requiredTools: string[];
	optionalTools: string[];
	externalMethods: string[];
	toolCalls: NonNullable<SecurityDedicatedSubagentDefinition["tools"]["toolCalls"]>;
	externalToolCalls: NonNullable<SecurityDedicatedSubagentDefinition["tools"]["externalToolCalls"]>;
	priorResultsUsed: string[];
	missingInformation: string[];
	initialIterationPlan: SecuritySubagentIterationPlan;
	executionDirectives: string[];
	handoffRequirements: string[];
	safetyChecks: string[];
}

export interface SecurityStepExecutionPlan {
	phase: SecurityWorkflowPhase;
	stepId: string;
	dedicatedSubagent: SecurityDedicatedSubagentDefinition | null;
	subagentDispatch: SecuritySubagentDelegation | null;
	objective: string;
	stepPrompt: string;
	requiredInformation: string[];
	priorResultsUsed: string[];
	missingInformation: string[];
	selectedToolCalls: SecurityStepToolCallPlan[];
	externalToolPrompts: SecurityExternalToolPrompt[];
	approvalPrompt: SecurityApprovalPrompt | null;
	nextDecisionInputs: string[];
	userApprovalRequiredBeforeNextStep: boolean;
	reportRequiredAfterStep: boolean;
	safetyChecks: string[];
}

export interface SecurityWorkflowStep {
	id: string;
	phase:
		| "clarify"
		| "asset_discovery"
		| "attack_surface_analysis"
		| "vulnerability_scanning"
		| "manual_validation"
		| "exploitation"
		| "privilege_escalation"
		| "attack_chain"
		| "risk_assessment"
		| "remediation"
		| "retest"
		| "closeout";
	agentRole:
		| "intent_router"
		| "web_research_agent"
		| "security_validator"
		| "memory_context"
		| "vulnerability_analyst"
		| "report_writer"
		| "payload_generator"
		| "asset_discovery_agent"
		| "attack_surface_analysis_agent"
		| "poc_research_agent";
	dedicatedSubagent?: SecurityDedicatedSubagentName;
	objective: string;
	stepPrompt: string;
	requiredInformation: string[];
	tools: string[];
	toolCallPlan: SecurityStepToolCallPlan[];
	externalToolPrompts: SecurityExternalToolPrompt[];
	methods: string[];
	requiresAuthorization: boolean;
	requiresUserApprovalBeforeStart: boolean;
	reportAfterStep: boolean;
	status: "pending";
}

export interface SecurityWorkflowPlan {
	mode: SecurityAgentMode;
	intent: SecurityIntentDecision;
	targets: string[];
	authorizationRequired: boolean;
	authorizationConfirmed: boolean;
	steps: SecurityWorkflowStep[];
	dedicatedSubagents: SecurityDedicatedSubagentDefinition[];
	recommendedAuthorizationScope: {
		targets: string[];
		allowedActions: string[];
		portScope: string;
		duration: string;
		confirmationRequired: string;
	};
	safetyBoundaries: string[];
}

const STANDARD_PENTEST_STEPS: SecurityWorkflowStep[] = [
	{
		id: "asset-discovery",
		phase: "asset_discovery",
		agentRole: "asset_discovery_agent",
		dedicatedSubagent: "asset_discovery",
		objective: "Discover in-scope assets, hosts, domains, exposed services, and third-party exposure.",
		stepPrompt:
			"Collect the authorized asset baseline before any deeper testing. Use security_scope_status first, then gather DNS/API/passive evidence and authorized service discovery results. Produce an asset inventory with sources, gaps, and recommended next checks.",
		requiredInformation: ["authorized targets", "asset inventory if supplied", "test window", "out-of-scope assets"],
		tools: [
			"security_delegate_subagent",
			"security_subagent_iteration_plan",
			"security_scope_status",
			"security_research",
			"api_client",
		],
		externalToolPrompts: externalPrompts("asset discovery", [
			"客户提供资产清单",
			"Whois / RDAP",
			"DNS 枚举",
			"Subfinder",
			"Nmap",
			"Amass",
			"Assetfinder",
			"SecurityTrails",
			"Censys",
			"Shodan",
			"FOFA / ZoomEye",
			"crt.sh",
			"GitHub / GitLab 搜索",
			"云资产盘点",
			"IP 反查",
			"ASN 查询",
		]),
		toolCallPlan: [
			toolPlan(
				"security_scope_status",
				"Verify the active authorization scope before touching targets.",
				true,
				["active authorization scope"],
				"scope status and allowed targets",
				"Always first for active assessment phases.",
			),
			toolPlan(
				"security_research",
				"Research passive public asset clues, source evidence, and coverage gaps.",
				false,
				["objective", "target URL or domain"],
				"passive public observations, candidate assets, source URLs, and evidence gaps",
				"Use after dedicated asset-discovery external methods produce public clues that need passive corroboration.",
			),
			toolPlan(
				"api_client",
				"Normalize structured DNS/IP metadata and API-accessible asset information.",
				false,
				["target host"],
				"DNS/IP metadata",
				"Use when dedicated asset-discovery output needs DNS, IP, repo, or cloud metadata normalization.",
			),
		],
		methods: [
			"DNS/API metadata lookup",
			"Nmap asset and port discovery output import",
			"authorized host and port inventory normalization",
			"evidence logging",
		],
		requiresAuthorization: true,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "attack-surface-analysis",
		phase: "attack_surface_analysis",
		agentRole: "attack_surface_analysis_agent",
		dedicatedSubagent: "attack_surface_analysis",
		objective: "Map exposed services, technologies, authentication surfaces, URLs, APIs, and likely entry points.",
		stepPrompt:
			"Turn the asset inventory into an attack-surface map. Use prior open services and URLs to inspect web surfaces, crawlable routes, API metadata, and reviewed external method output when authorized. Output entry points, technologies, authentication boundaries, and evidence gaps.",
		requiredInformation: ["asset discovery output", "open ports", "HTTP endpoints", "technology fingerprints"],
		tools: [
			"security_delegate_subagent",
			"security_subagent_iteration_plan",
			"security_memory",
			"security_web_analysis",
			"security_crawl",
			"security_external_tool_runner",
			"api_client",
			"security_report",
		],
		externalToolPrompts: externalPrompts("attack surface analysis", [
			"Service Discovery",
			"HTTP Surface Discovery",
			"Technology Fingerprinting",
			"Visual Surface Analysis",
			"Route Discovery",
			"Web Crawling",
			"JavaScript Analysis",
			"API & Metadata Discovery",
		]),
		toolCallPlan: [
			toolPlan(
				"security_memory",
				"Recall asset discovery handoff and store the completed attack surface map.",
				true,
				["asset discovery handoff", "surface map summary"],
				"recalled asset context or stored attack surface evidence",
				"Use at the start and end of attack surface analysis.",
			),
			toolPlan(
				"security_web_analysis",
				"Analyze HTTP endpoints for headers, title, links, scripts, metadata, technologies, and auth indicators.",
				false,
				["authorized HTTP/HTTPS URLs"],
				"web page/header analysis",
				"Use for HTTP/HTTPS services discovered earlier.",
			),
			toolPlan(
				"security_crawl",
				"Crawl bounded same-domain URLs for routes, forms, docs, API hints, and JavaScript-linked paths.",
				false,
				["start URL", "crawl limits"],
				"route/API/JS link inventory",
				"Use when a web app has crawlable content and crawl is within scope.",
			),
			toolPlan(
				"security_external_tool_runner",
				"Run or import reviewed external method output for service, HTTP, technology, visual, route, crawl, JS, or API discovery.",
				false,
				["approved external method", "reviewed command or output file", "target"],
				"bounded external method output",
				"Use after scope status confirms authorization and the selected external method is explained.",
			),
			toolPlan(
				"api_client",
				"Inspect robots, sitemap, OpenAPI, DNS, IP, or public metadata endpoints.",
				false,
				["URL or preset query"],
				"API/metadata response",
				"Use when metadata endpoints are likely or prior page extraction found API docs.",
			),
			toolPlan(
				"security_report",
				"Save or assemble the attack surface handoff for PoC research.",
				false,
				["scope", "attack surface map", "methodology", "limitations"],
				"attack surface report or saved report paths",
				"Use when the user wants a report or the next phase needs a durable handoff.",
			),
		],
		methods: [
			"Service Discovery",
			"HTTP Surface Discovery",
			"Technology Fingerprinting",
			"Visual Surface Analysis",
			"Route Discovery",
			"Web Crawling",
			"JavaScript Analysis",
			"API & Metadata Discovery",
		],
		requiresAuthorization: true,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "vulnerability-scanning",
		phase: "vulnerability_scanning",
		agentRole: "poc_research_agent",
		dedicatedSubagent: "poc_research",
		objective:
			"Research PoC availability for collected services, middleware, products, versions, and CVEs, then correlate known-vulnerability evidence.",
		stepPrompt:
			"Use the asset discovery and attack-surface outputs as the source of truth. Extract observed services, middleware, products, versions, CVEs, and risky configurations, then research whether matching public PoCs or exploit references exist. Query vulnerability databases and Web sources, capture references and caveats, correlate evidence into defensive findings, then generate and save a report under reports/.",
		requiredInformation: [
			"attack surface map",
			"observed services and middleware",
			"product versions where available",
			"scanner limitations",
		],
		tools: [
			"security_delegate_subagent",
			"security_subagent_iteration_plan",
			"security_scope_status",
			"security_memory",
			"api_client",
			"security_research",
			"security_terminal_session",
			"security_assessment",
			"security_report",
		],
		externalToolPrompts: externalPrompts("vulnerability scanning", [
			"NVD",
			"CVE.org",
			"MITRE ATT&CK",
			"GitHub Security Advisories",
			"Exploit and public PoC references",
			"Public advisory and writeup sources",
			"Network and application scanner import",
			"Supply-chain and code scanner import",
			"Vendor advisories",
		]),
		toolCallPlan: [
			toolPlan(
				"security_scope_status",
				"Verify authorization before target-bound research or scanner import/execution.",
				true,
				["active authorization scope"],
				"scope status and allowed targets",
				"Always before target_url research, scanner import workflows, or terminal execution.",
			),
			toolPlan(
				"security_memory",
				"Recall service/middleware evidence and store final PoC research conclusions.",
				true,
				["attack surface handoff", "service/middleware query"],
				"recalled service context or stored PoC research notes",
				"Use at the start and end of PoC research.",
			),
			toolPlan(
				"api_client",
				"Query structured vulnerability metadata sources for collected services and middleware.",
				true,
				["observed service, middleware, product/version, CVE, or service keyword"],
				"normalized vulnerability records",
				"Use for every observed product/version, CVE, or risky service.",
			),
			toolPlan(
				"security_research",
				"Research public advisories, Exploit-DB pages, vendor notes, GitHub context, and PoC references.",
				true,
				["observed service or middleware plus version", "PoC or exploit reference query"],
				"source URLs, snippets, and PoC availability notes",
				"Use after structured metadata when public-reference context is missing or weakly structured.",
			),
			toolPlan(
				"security_terminal_session",
				"Import approved scanner output or run explicitly approved non-exploit scanner metadata commands.",
				false,
				["active authorization", "scanner category", "approved scanner command or output file"],
				"scanner observations",
				"Use when imported scanner output is available or the user authorized scanner/template metadata collection.",
			),
			toolPlan(
				"security_assessment",
				"Correlate discovery, headers, and vulnerability records into findings.",
				true,
				["scope", "discovered hosts", "header checks", "vulnerability records"],
				"defensive findings and limitations",
				"Always use after collecting scan or vulnerability evidence.",
			),
			toolPlan(
				"security_report",
				"Save the vulnerability scan report to reports/.",
				true,
				["scope", "methodology", "findings", "save_to_reports=true"],
				"Markdown/JSON report paths",
				"Always use after vulnerability scanning.",
			),
		],
		methods: [
			"known CVE lookup",
			"public PoC reference research",
			"template/scanner result ingestion",
			"weak configuration correlation",
		],
		requiresAuthorization: true,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: true,
		status: "pending",
	},
	{
		id: "manual-validation",
		phase: "manual_validation",
		agentRole: "security_validator",
		objective: "Validate scanner findings manually, remove false positives, and capture reproducible evidence.",
		stepPrompt:
			"Validate the reported findings manually. Choose request replay, API calls, page extraction, or bounded terminal commands based on the evidence. Use the payload prompt tool only to draft safe candidate probes, then review them before use.",
		requiredInformation: ["scanner report", "test accounts if needed", "expected business behavior"],
		tools: ["security_terminal_session", "api_client", "page_extract", "security_payload_model_prompt"],
		externalToolPrompts: externalPrompts("manual validation", [
			"请求重放",
			"参数篡改",
			"权限边界测试",
			"输入点测试",
			"业务流程测试",
			"Session 测试",
			"认证测试",
			"文件上传测试",
			"API 测试",
			"日志和错误信息分析",
			"影响复现",
			"Burp Suite",
			"OWASP ZAP",
			"Postman",
			"Insomnia",
			"curl / HTTPie",
			"Browser DevTools",
			"JWT.io",
			"CyberChef",
			"jq",
		]),
		toolCallPlan: [
			toolPlan(
				"security_payload_model_prompt",
				"Draft safe validation payloads or commands for main-model review.",
				true,
				["finding", "authorized target", "constraints"],
				"candidate JSON with safety checks",
				"Use before any manual validation payload or risky command.",
			),
			toolPlan(
				"api_client",
				"Replay or construct safe API/HTTP validation requests.",
				true,
				["endpoint", "method", "parameters"],
				"HTTP/API response evidence",
				"Use for API, auth, IDOR, header, and configuration findings.",
			),
			toolPlan(
				"page_extract",
				"Inspect affected pages and evidence context.",
				false,
				["URL"],
				"page text/metadata",
				"Use when visual/page content affects validation.",
			),
			toolPlan(
				"security_terminal_session",
				"Run approved local clients such as curl/httpie/jq or scanner validation commands.",
				false,
				["reviewed command"],
				"command output",
				"Use only for authorized commands after explaining them.",
			),
		],
		methods: ["request replay", "role-boundary checks", "input validation tests", "evidence comparison"],
		requiresAuthorization: true,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "vulnerability-exploitation",
		phase: "exploitation",
		agentRole: "payload_generator",
		objective: "Prove authorized vulnerability impact with minimal, reversible, non-destructive actions.",
		stepPrompt:
			"Only if explicitly authorized, prove impact with minimal safe actions. Generate candidate proof payloads with the small-model prompt tool, have the main model reject anything outside scope, then use only non-destructive execution paths.",
		requiredInformation: [
			"validated finding",
			"explicit exploit authorization",
			"safe proof objective",
			"rollback plan",
		],
		tools: ["security_scope_status", "security_payload_model_prompt", "security_terminal_session"],
		externalToolPrompts: externalPrompts("safe proof of impact", [
			"Burp Suite",
			"SQLMap / 手工验证",
			"浏览器、Burp",
			"Burp Collaborator / interactsh",
			"自建回连服务 / Collaborator",
			"安全 PoC",
			"WebShell 模拟文件 / 受控测试文件",
			"ysoserial",
			"手工 payload",
			"Hydra / Medusa / Ncrack",
			"Metasploit / Nuclei / Exploit-DB PoC",
			"多账号对比",
			"云 CLI / ScoutSuite / Prowler",
		]),
		toolCallPlan: [
			toolPlan(
				"security_scope_status",
				"Reconfirm exploit/proof-of-impact authorization.",
				true,
				["active authorization scope"],
				"scope status",
				"Always before proof-of-impact steps.",
			),
			toolPlan(
				"security_payload_model_prompt",
				"Draft minimal non-destructive proof payloads or commands.",
				true,
				["validated finding", "safe proof objective", "constraints"],
				"candidate proof payloads and safety checks",
				"Use for any payload or command candidate.",
			),
			toolPlan(
				"security_terminal_session",
				"Execute only reviewed, authorized, non-destructive proof commands.",
				false,
				["reviewed command", "rollback plan"],
				"proof evidence",
				"Use only after explicit user approval for the exact action.",
			),
		],
		methods: ["safe PoC construction", "main-model review", "bounded execution", "impact evidence capture"],
		requiresAuthorization: true,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "privilege-escalation",
		phase: "privilege_escalation",
		agentRole: "security_validator",
		objective: "Assess whether authorized low-privilege access can become higher-impact access.",
		stepPrompt:
			"Assess privilege escalation only when the user explicitly authorized this phase and supplied the current access context. Prefer configuration and permission review; do not run destructive or persistence actions.",
		requiredInformation: ["existing access level", "system type", "explicit approval for local/cloud/AD checks"],
		tools: ["security_scope_status", "security_terminal_session", "security_payload_model_prompt"],
		externalToolPrompts: externalPrompts("privilege escalation assessment", [
			"LinPEAS",
			"Linux Exploit Suggester",
			"WinPEAS",
			"Seatbelt",
			"PowerUp",
			"BloodHound",
			"SharpHound",
			"PowerView",
			"LaZagne",
			"sudo -l / 服务权限 / SUID",
			"IAM 权限分析",
			"Capabilities / 挂载检查",
			"RBAC 检查",
			"内核漏洞",
			"弱文件权限",
			"SUID/SGID 滥用",
			"sudo 配置错误",
			"计划任务滥用",
			"服务权限错误",
			"明文凭据",
			"Token / Session 滥用",
			"过度 IAM 权限",
		]),
		toolCallPlan: [
			toolPlan(
				"security_scope_status",
				"Confirm privilege-escalation assessment is in scope.",
				true,
				["active authorization scope"],
				"scope status",
				"Always before privilege checks.",
			),
			toolPlan(
				"security_payload_model_prompt",
				"Draft safe audit commands for permission/configuration checks.",
				true,
				["system type", "current access level"],
				"candidate audit commands",
				"Use before suggesting local/cloud/AD checks.",
			),
			toolPlan(
				"security_terminal_session",
				"Run reviewed read-only privilege/configuration checks.",
				false,
				["reviewed command"],
				"permission/config evidence",
				"Use only for approved non-destructive checks.",
			),
		],
		methods: ["configuration review", "permission audit", "non-destructive privilege path validation"],
		requiresAuthorization: true,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "attack-chain-composition",
		phase: "attack_chain",
		agentRole: "vulnerability_analyst",
		objective: "Combine findings into realistic attack paths and business-impact narratives.",
		stepPrompt:
			"Use validated findings and asset context to model realistic attack chains. Do not create new exploit actions; combine evidence into business-risk paths and identify missing proof points.",
		requiredInformation: ["validated findings", "asset criticality", "data sensitivity", "identity boundaries"],
		tools: ["security_memory", "security_vulnerability_assessment"],
		externalToolPrompts: externalPrompts("attack chain composition", [
			"子域接管 -> 钓鱼 -> 凭据泄露",
			"信息泄露 -> API 越权 -> 数据导出",
			"SSRF -> 云元数据访问 -> 云凭据泄露",
			"文件上传 -> WebShell -> 内网探测",
			"SQL 注入 -> 数据库权限 -> 文件写入",
			"弱口令 -> VPN 登录 -> 内网横向移动",
			"Git 泄露 -> 配置密钥 -> 后台登录",
			"XSS -> 管理员会话 -> 后台操作",
			"Jenkins 弱口令 -> 构建脚本执行 -> 主机权限",
			"Kubernetes Dashboard 暴露 -> Pod 创建 -> 集群权限",
			"Kill Chain 建模",
			"ATT&CK 映射",
			"权限路径图",
			"数据流分析",
			"业务影响建模",
		]),
		toolCallPlan: [
			toolPlan(
				"security_memory",
				"Recall prior findings, scope, report summaries, and next-step notes.",
				true,
				["query for target and findings"],
				"relevant security context",
				"Always before attack-chain modeling.",
			),
			toolPlan(
				"security_vulnerability_assessment",
				"Re-correlate findings into chain-relevant impacts and limitations.",
				true,
				["validated findings", "asset criticality"],
				"correlated risk findings",
				"Use to ground chains in collected evidence.",
			),
		],
		methods: ["kill-chain mapping", "ATT&CK mapping", "business impact modeling"],
		requiresAuthorization: false,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "risk-assessment",
		phase: "risk_assessment",
		agentRole: "vulnerability_analyst",
		objective: "Rate severity, likelihood, scope, exploitability, and remediation priority.",
		stepPrompt:
			"Rate risk from validated evidence, not assumptions. Use vulnerability assessment and any supplied detection/log evidence to assign severity, likelihood, exposure, and remediation priority.",
		requiredInformation: ["validated evidence", "business context", "existing controls", "exposure level"],
		tools: ["security_vulnerability_assessment", "security_detection_analysis"],
		externalToolPrompts: externalPrompts("risk assessment", [
			"CVSS",
			"OWASP Risk Rating",
			"DREAD",
			"STRIDE",
			"MITRE ATT&CK",
			"业务影响评估",
			"可利用性评估",
			"资产重要性评估",
			"横向移动能力",
			"检测难度",
		]),
		toolCallPlan: [
			toolPlan(
				"security_vulnerability_assessment",
				"Produce or refresh severity-ranked findings from evidence.",
				true,
				["validated evidence", "scope"],
				"severity-ranked findings",
				"Always for risk scoring.",
			),
			toolPlan(
				"security_detection_analysis",
				"Analyze supplied logs/alerts/flows for detection and exploitability context.",
				false,
				["events or logs"],
				"detection findings",
				"Use when the user supplied logs, alerts, SIEM snippets, or flow events.",
			),
		],
		methods: ["CVSS/OWASP-style scoring", "likelihood-impact matrix", "control-gap analysis"],
		requiresAuthorization: false,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "remediation-recommendations",
		phase: "remediation",
		agentRole: "report_writer",
		objective: "Provide prioritized, actionable remediation and verification guidance.",
		stepPrompt:
			"Convert risk-ranked findings into owner-ready remediation. Include immediate mitigation, full fix, verification method, and priority. Persist the remediation summary in security memory.",
		requiredInformation: ["risk-ranked findings", "affected owners", "technical constraints"],
		tools: ["security_report", "security_memory"],
		externalToolPrompts: externalPrompts("remediation planning", [
			"SQL 注入修复",
			"XSS 修复",
			"CSRF 修复",
			"SSRF 修复",
			"RCE 修复",
			"文件上传修复",
			"越权修复",
			"弱口令修复",
			"敏感信息泄露修复",
			"默认配置修复",
			"过度权限修复",
			"组件漏洞修复",
			"TLS 问题修复",
			"CORS 错误修复",
			"云存储桶公开修复",
			"Kubernetes 风险修复",
			"日志不足修复",
		]),
		toolCallPlan: [
			toolPlan(
				"security_report",
				"Update or generate remediation-focused report content.",
				true,
				["findings", "remediation", "verification method"],
				"report content or paths",
				"Always after risk assessment.",
			),
			toolPlan(
				"security_memory",
				"Store remediation decisions and next-step recommendations.",
				true,
				["summary content"],
				"memory item",
				"Always after remediation recommendations.",
			),
		],
		methods: ["fix guidance", "temporary mitigation", "verification steps", "owner-ready summary"],
		requiresAuthorization: false,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "retest",
		phase: "retest",
		agentRole: "security_validator",
		objective: "Confirm fixes are effective and no obvious regressions were introduced.",
		stepPrompt:
			"Retest fixed findings by replaying the original safe checks and comparing results. Use only the tools relevant to the original finding and record fixed/partial/unfixed status.",
		requiredInformation: ["fixed finding list", "original reproduction evidence", "change window"],
		tools: [
			"security_scope_status",
			"security_terminal_session",
			"security_header_check",
			"security_vulnerability_assessment",
		],
		externalToolPrompts: externalPrompts("retest", [
			"原始 PoC 重放",
			"Burp Repeater",
			"自动扫描复测",
			"权限回归测试",
			"单元/集成测试",
			"代码审查",
			"配置审计",
			"日志验证",
			"旁路测试",
			"回归扫描",
		]),
		toolCallPlan: [
			toolPlan(
				"security_scope_status",
				"Confirm retest scope and time window.",
				true,
				["active authorization scope"],
				"scope status",
				"Always before retesting.",
			),
			toolPlan(
				"security_header_check",
				"Retest HTTP header/configuration fixes.",
				false,
				["URL"],
				"header retest evidence",
				"Use for HTTP header findings.",
			),
			toolPlan(
				"security_terminal_session",
				"Run reviewed retest commands or scanner checks.",
				false,
				["reviewed retest command"],
				"retest output",
				"Use when the original finding used a command/scanner.",
			),
			toolPlan(
				"security_vulnerability_assessment",
				"Summarize fixed, partial, or remaining risk.",
				true,
				["original evidence", "retest evidence"],
				"retest assessment",
				"Always after retest evidence is collected.",
			),
		],
		methods: ["original PoC replay where safe", "scanner retest", "role regression check", "residual risk capture"],
		requiresAuthorization: true,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
	{
		id: "closeout",
		phase: "closeout",
		agentRole: "report_writer",
		objective: "Finalize deliverables, memory summary, residual risk, and closure status.",
		stepPrompt:
			"Finalize the engagement artifacts. Produce final report/status, residual risk, retest status, and store a concise memory summary so short continuation requests can resume correctly.",
		requiredInformation: ["final findings", "retest status", "accepted residual risks"],
		tools: ["security_report", "security_memory"],
		externalToolPrompts: externalPrompts("closeout deliverables", [
			"渗透测试授权书",
			"资产清单",
			"漏洞报告",
			"风险矩阵",
			"攻击链说明",
			"复测报告",
			"管理层摘要",
			"技术附录",
		]),
		toolCallPlan: [
			toolPlan(
				"security_report",
				"Generate final report, executive summary, and technical appendix.",
				true,
				["final findings", "retest status", "residual risks"],
				"final report paths/content",
				"Always at closeout.",
			),
			toolPlan(
				"security_memory",
				"Persist final scope, conclusions, and follow-up recommendations.",
				true,
				["closeout summary"],
				"memory snapshot",
				"Always at closeout.",
			),
		],
		methods: ["final report assembly", "executive summary", "technical appendix", "memory persistence"],
		requiresAuthorization: false,
		requiresUserApprovalBeforeStart: true,
		reportAfterStep: false,
		status: "pending",
	},
];

export function buildSecurityWorkflowPlan(input: SecurityWorkflowInput): SecurityWorkflowPlan {
	const objective = input.objective.trim();
	if (!objective) throw new Error("objective is required");
	const intent = classifySecurityIntent(objective);
	const targets = normalizeTargets(input.targets && input.targets.length > 0 ? input.targets : intent.focus);
	const includeExploration = input.includeExploration ?? intent.needsExplore;
	const includeActiveValidation = input.includeActiveValidation ?? intent.needsAuthorization;
	const includeReport = input.includeReport ?? intent.needsReport;
	const mode = chooseMode(input.complexity, intent, includeActiveValidation, includeExploration);
	const authorizationRequired = includeActiveValidation || intent.needsAuthorization;
	const authorizationConfirmed = input.authorizationConfirmed === true;
	const steps: SecurityWorkflowStep[] = [
		{
			id: "route-intent",
			phase: "clarify",
			agentRole: "intent_router",
			objective: "Classify the request, extract targets, and identify authorization gaps.",
			stepPrompt:
				"Classify the user request, recover recent security context if this is a continuation, inspect authorization status, and identify the next concrete phase.",
			requiredInformation: ["user objective", "targets", "authorization status"],
			tools: ["security_scope_status", "security_memory"],
			externalToolPrompts: [],
			toolCallPlan: [
				toolPlan(
					"security_scope_status",
					"Inspect current authorization before planning active work.",
					true,
					[],
					"authorization status",
					"Always for security tasks.",
				),
				toolPlan(
					"security_memory",
					"Recover prior target, report summary, and next-step notes.",
					true,
					["objective or target query"],
					"relevant memories",
					"Use for continuation or complex workflows.",
				),
			],
			methods: ["intent classification", "scope gap analysis", "recent security memory recall"],
			requiresAuthorization: false,
			requiresUserApprovalBeforeStart: false,
			reportAfterStep: false,
			status: "pending",
		},
	];

	if (authorizationRequired && !authorizationConfirmed) {
		steps.push({
			id: "confirm-scope",
			phase: "clarify",
			agentRole: "intent_router",
			objective:
				"Ask for explicit target, scope, permitted action categories, and duration before active validation.",
			stepPrompt:
				"Recommend a conservative authorization scope, ask the user to explicitly confirm targets, allowed actions, port scope, duration, and emergency contact, then record it only after confirmation.",
			requiredInformation: ["approved targets", "allowed actions", "port scope", "expiry", "business reason"],
			tools: ["security_authorize_scope", "security_scope_status"],
			externalToolPrompts: [],
			toolCallPlan: [
				toolPlan(
					"security_scope_status",
					"Show whether a scope already exists.",
					true,
					[],
					"authorization status",
					"Use before asking for missing scope.",
				),
				toolPlan(
					"security_authorize_scope",
					"Record the explicit user-approved scope.",
					true,
					["targets", "allowed actions", "expiry", "reason"],
					"stored authorization scope",
					"Use only after explicit user confirmation.",
				),
			],
			methods: ["suggest conservative authorization scope", "record only explicit user approval"],
			requiresAuthorization: false,
			requiresUserApprovalBeforeStart: false,
			reportAfterStep: false,
			status: "pending",
		});
	}

	if (includeExploration || includeActiveValidation || includeReport) {
		steps.push(...STANDARD_PENTEST_STEPS);
	}

	return {
		mode,
		intent,
		targets,
		authorizationRequired,
		authorizationConfirmed,
		steps,
		dedicatedSubagents: SECURITY_DEDICATED_SUBAGENTS,
		recommendedAuthorizationScope: {
			targets: targets.length > 0 ? targets : ["<user-approved target or CIDR>"],
			allowedActions: [
				"asset_discovery",
				"attack_surface_analysis",
				"vulnerability_scanning",
				"manual_validation",
				"safe_proof_of_impact",
				"retest",
			],
			portScope: "Start with common/web ports, then request explicit approval before full TCP 1-65535 discovery.",
			duration: "Default 1 hour unless the user states a shorter test window.",
			confirmationRequired:
				"Any new target, broader CIDR, full-port discovery, exploitation, privilege escalation, or credentialed test requires explicit user confirmation.",
		},
		safetyBoundaries: [
			"No security tool or command execution without an active authorization scope.",
			"Read-only exploration does not imply authorization for network-impacting validation.",
			"Active validation must be bounded to explicitly authorized targets, action categories, and duration.",
			"Before every workflow step, produce a step plan covering required information, purpose, tools, and method.",
			"After every completed step, ask the user for approval before starting the next step.",
		],
	};
}

export function buildSecurityStepExecutionPlan(input: SecurityStepExecutionPlanInput): SecurityStepExecutionPlan {
	const objective = input.objective.trim();
	if (!objective) throw new Error("objective is required");
	const step = findStepByPhase(input.phase);
	const dedicatedSubagent = step.dedicatedSubagent
		? getSecurityDedicatedSubagentDefinition(step.dedicatedSubagent)
		: null;
	const priorResults = normalizeTexts(input.priorResults ?? []);
	const providedMissingInformation = normalizeTexts(input.missingInformation ?? []);
	const missingInformation = mergeUnique([
		...providedMissingInformation,
		...step.requiredInformation.filter((item) => !hasEvidenceFor(item, priorResults)),
	]);
	const selectedToolCalls = selectToolCalls(
		step,
		priorResults,
		missingInformation,
		input.authorizationConfirmed === true,
	);
	return {
		phase: step.phase,
		stepId: step.id,
		dedicatedSubagent,
		subagentDispatch: step.dedicatedSubagent
			? buildSecuritySubagentDelegation({
					subagent: step.dedicatedSubagent,
					phase: step.phase,
					objective,
					targets: input.targets,
					priorResults,
					missingInformation,
				})
			: null,
		objective: step.objective,
		stepPrompt: renderStepPrompt(step, objective, input.targets ?? [], priorResults, missingInformation),
		requiredInformation: step.requiredInformation,
		priorResultsUsed: priorResults,
		missingInformation,
		selectedToolCalls,
		externalToolPrompts: step.externalToolPrompts,
		approvalPrompt: step.requiresUserApprovalBeforeStart
			? buildApprovalPrompt(step, objective, input.targets ?? [])
			: null,
		nextDecisionInputs: buildNextDecisionInputs(step),
		userApprovalRequiredBeforeNextStep: step.requiresUserApprovalBeforeStart,
		reportRequiredAfterStep: step.reportAfterStep,
		safetyChecks: [
			step.requiresAuthorization
				? "Call security_scope_status and confirm active authorization before active tool execution."
				: "Do not infer active authorization from this planning step.",
			"Use selected tools to collect evidence before moving to analysis or the next phase.",
			"After this phase, ask the user to approve the next phase before continuing.",
			"Any new target, broader port scope, exploitation, privilege escalation, credentialed test, or destructive action requires explicit user confirmation.",
		],
	};
}

export function buildSecuritySubagentDelegation(input: SecuritySubagentDelegationInput): SecuritySubagentDelegation {
	const objective = input.objective.trim();
	if (!objective) throw new Error("objective is required");
	const definition = getSecurityDedicatedSubagentDefinition(input.subagent);
	const priorResults = normalizeTexts(input.priorResults ?? []);
	const missingInformation = normalizeTexts(input.missingInformation ?? []);
	const targets = normalizeTargets(input.targets ?? []);
	return {
		subagent: definition.name,
		displayName: definition.displayName,
		role: definition.model.role,
		phase: input.phase,
		objective,
		targets,
		systemPrompt: definition.prompt.systemPrompt,
		handoffPrompt: definition.prompt.handoffPrompt,
		mission: definition.mission,
		focus: definition.focus,
		requiredInputs: definition.requiredInputs,
		produces: definition.produces,
		boundaries: definition.boundaries,
		memory: definition.memory,
		requiredTools: definition.tools.requiredTools,
		optionalTools: definition.tools.optionalTools,
		externalMethods: definition.tools.externalMethods,
		toolCalls: definition.tools.toolCalls ?? [],
		externalToolCalls: definition.tools.externalToolCalls ?? [],
		priorResultsUsed: priorResults,
		missingInformation,
		initialIterationPlan: buildSecuritySubagentIterationPlan({
			subagent: definition.name,
			phase: input.phase,
			objective,
			targets,
			priorResults,
			missingInformation,
			iteration: 1,
		}),
		executionDirectives: [
			`Run this phase as ${definition.displayName}; do not blend responsibilities with other security phases.`,
			"Call security_subagent_iteration_plan before the first phase tool call, then again after each tool round with collected evidence, missing information, and tool errors.",
			"Use this subagent systemPrompt as the phase-local instruction set before selecting tools.",
			"Use externalToolCalls/externalMethods as the primary method list when the subagent prompt says external-first.",
			"Call requiredTools and required toolCalls when their required inputs are available and safety constraints are satisfied.",
			"Use optional built-in tools to corroborate, normalize, validate, remember, and report evidence.",
			"Continue replanning until the iteration plan decision is complete or manual_intervention.",
			"Persist useful evidence with security_memory before returning only this subagent's produced handoff fields, evidence sources, limitations, and unresolved gaps.",
		],
		handoffRequirements: definition.memory.handoff,
		safetyChecks: [
			"Stay inside explicit authorization scope and phase boundaries.",
			"Do not infer authorization from passive results, external platform data, or prior memory.",
			"Do not execute exploits, destructive actions, persistence, credential theft, or lateral movement.",
			"Ask for explicit user approval before new targets, broader port scope, active validation, or reviewed terminal commands.",
		],
	};
}

export function buildSecuritySubagentIterationPlan(
	input: SecuritySubagentIterationPlanInput,
): SecuritySubagentIterationPlan {
	const objective = input.objective.trim();
	if (!objective) throw new Error("objective is required");
	const definition = getSecurityDedicatedSubagentDefinition(input.subagent);
	const iteration = Math.max(1, Math.trunc(input.iteration ?? 1));
	const maxIterations = Math.max(1, Math.trunc(input.maxIterations ?? 4));
	const targets = normalizeTargets(input.targets ?? []);
	const priorResults = normalizeTexts(input.priorResults ?? []);
	const collectedEvidence = normalizeTexts(input.collectedEvidence ?? []);
	const missingInformation = normalizeTexts(input.missingInformation ?? []);
	const completedObjectives = normalizeTexts(input.completedObjectives ?? []);
	const toolErrors = normalizeTexts(input.toolErrors ?? []);
	const evidence = [...priorResults, ...collectedEvidence, ...completedObjectives];
	const completionCriteria = mergeUnique([...definition.produces, ...definition.memory.handoff]);
	const achievedCriteria = completionCriteria.filter((criterion) => hasEvidenceFor(criterion, evidence));
	const baseRemainingCriteria = mergeUnique([
		...completionCriteria.filter((criterion) => !achievedCriteria.includes(criterion)),
		...missingInformation,
	]);
	const memoryPersisted = hasMemoryPersistenceEvidence(evidence);
	const expectedEvidenceCollected = baseRemainingCriteria.length === 0 && collectedEvidence.length > 0;
	const remainingCriteria = mergeUnique([
		...baseRemainingCriteria,
		...(expectedEvidenceCollected && !memoryPersisted ? ["security memory persistence"] : []),
	]);
	const repeatedErrors = toolErrors.length >= 2;
	const exhaustedIterations = iteration >= maxIterations && remainingCriteria.length > 0;
	const decision: SecuritySubagentIterationDecision =
		repeatedErrors || exhaustedIterations
			? "manual_intervention"
			: expectedEvidenceCollected && memoryPersisted
				? "complete"
				: "continue";
	const nextToolCalls =
		decision === "continue"
			? selectSubagentToolCalls(definition, evidence, remainingCriteria, toolErrors, expectedEvidenceCollected)
			: [];
	const nextExternalMethods =
		decision === "continue" ? selectSubagentExternalMethods(definition, evidence, remainingCriteria, toolErrors) : [];
	const operatorChoicePrompt = buildOperatorChoicePrompt(
		definition,
		objective,
		targets,
		decision,
		toolErrors,
		remainingCriteria,
	);
	return {
		subagent: definition.name,
		displayName: definition.displayName,
		phase: input.phase,
		iteration,
		maxIterations,
		decision,
		objective,
		targets,
		completionCriteria,
		achievedCriteria,
		remainingCriteria,
		memoryPersisted,
		readyForNextPhase: decision === "complete" && memoryPersisted,
		nextToolCalls,
		nextExternalMethods,
		fallbackActions: buildSubagentFallbackActions(definition, toolErrors, remainingCriteria),
		operatorChoicePrompt,
		manualInterventionPrompt: decision === "manual_intervention" ? operatorChoicePrompt : null,
		memoryActions: buildSubagentMemoryActions(definition, decision),
		stopReason:
			decision === "complete"
				? `${definition.displayName} has enough evidence for its expected handoff.`
				: decision === "manual_intervention"
					? `${definition.displayName} needs manual choice because errors or unresolved gaps block safe progress.`
					: null,
		replanInputsForNextRound: [
			"new evidence collected this round",
			"tool outputs or imported external method output",
			"new missing information or confidence gaps",
			"tool errors and fallback attempts",
			"manual decisions or approval results",
		],
	};
}

function chooseMode(
	complexity: SecurityWorkflowInput["complexity"],
	intent: SecurityIntentDecision,
	includeActiveValidation: boolean,
	includeExploration: boolean,
): SecurityAgentMode {
	if (complexity === "simple") return "react";
	if (complexity === "complex" || intent.intent === "security_task_complex") {
		return includeActiveValidation && includeExploration ? "multi_agent_coordination" : "plan_execute";
	}
	return includeExploration ? "plan_execute" : "react";
}

function normalizeTargets(values: string[]): string[] {
	const normalized = values.map((value) => value.trim()).filter(Boolean);
	return [...new Set(normalized)].slice(0, 20);
}

function toolPlan(
	tool: string,
	purpose: string,
	required: boolean,
	inputsNeeded: string[],
	expectedOutput: string,
	useWhen: string,
): SecurityStepToolCallPlan {
	return { tool, purpose, required, inputsNeeded, expectedOutput, useWhen };
}

function externalPrompts(phase: string, tools: string[]): SecurityExternalToolPrompt[] {
	return tools.map((tool) => ({
		tool,
		prompt: [
			`External tool/method: ${tool}`,
			`Phase: ${phase}`,
			"Use only if the active authorization, target scope, test window, and constraints allow it.",
			"Use this as a prompt for a reviewed terminal command, API request, manual validation step, imported output, or report task when this external method is the best fit for the dedicated subagent phase.",
			"State exactly what information this tool should collect and how its output will affect the next step.",
		].join("\n"),
		useWhen: `Use during ${phase} when prior results or missing information show ${tool} is the most appropriate way to collect required evidence.`,
		safetyConstraints: [
			"Do not run outside explicitly authorized targets, action categories, port scope, or time window.",
			"Do not execute destructive, persistence, credential-theft, stealth, lateral-movement, or exfiltration behavior.",
			"Explain and review any command or payload before execution; request explicit confirmation for new scope or higher-risk actions.",
		],
	}));
}

function findStepByPhase(phase: SecurityWorkflowPhase): SecurityWorkflowStep {
	const steps = [
		...STANDARD_PENTEST_STEPS,
		{
			id: "route-intent",
			phase: "clarify" as const,
			agentRole: "intent_router" as const,
			objective: "Classify the request, extract targets, and identify authorization gaps.",
			stepPrompt:
				"Classify the user request, recover recent security context if this is a continuation, inspect authorization status, and identify the next concrete phase.",
			requiredInformation: ["user objective", "targets", "authorization status"],
			tools: ["security_scope_status", "security_memory"],
			toolCallPlan: [
				toolPlan(
					"security_scope_status",
					"Inspect current authorization before planning active work.",
					true,
					[],
					"authorization status",
					"Always for security tasks.",
				),
				toolPlan(
					"security_memory",
					"Recover prior target, report summary, and next-step notes.",
					true,
					["objective or target query"],
					"relevant memories",
					"Use for continuation or complex workflows.",
				),
			],
			externalToolPrompts: [],
			methods: ["intent classification", "scope gap analysis", "recent security memory recall"],
			requiresAuthorization: false,
			requiresUserApprovalBeforeStart: false,
			reportAfterStep: false,
			status: "pending" as const,
		},
	];
	const step = steps.find((candidate) => candidate.phase === phase);
	if (!step) throw new Error(`Unknown security workflow phase: ${phase}`);
	return step;
}

function selectToolCalls(
	step: SecurityWorkflowStep,
	priorResults: string[],
	missingInformation: string[],
	authorizationConfirmed: boolean,
): SecurityStepToolCallPlan[] {
	const selected = step.toolCallPlan.filter((plan) => {
		if (plan.required) return true;
		const haystack = `${priorResults.join("\n")} ${missingInformation.join("\n")}`.toLowerCase();
		return plan.inputsNeeded.some((input) => haystack.includes(input.toLowerCase())) || haystack.includes(plan.tool);
	});
	const delegationPlan = step.dedicatedSubagent
		? [
				toolPlan(
					"security_delegate_subagent",
					`Invoke the ${getSecurityDedicatedSubagentDefinition(step.dedicatedSubagent).displayName} execution contract for this phase.`,
					true,
					["subagent", "phase", "objective", "targets", "prior_results", "missing_information"],
					"dedicated subagent dispatch packet with prompt, memory, built-in tools, external methods, and handoff requirements",
					"Always first for asset discovery, attack surface analysis, and PoC research phases.",
				),
			]
		: [];
	const iterationPlan = step.dedicatedSubagent
		? [
				toolPlan(
					"security_subagent_iteration_plan",
					`Plan the next ${getSecurityDedicatedSubagentDefinition(step.dedicatedSubagent).displayName} iteration from evidence, gaps, and errors.`,
					true,
					[
						"subagent",
						"phase",
						"objective",
						"targets",
						"prior_results",
						"collected_evidence",
						"missing_information",
						"tool_errors",
					],
					"continue, complete, or manual_intervention decision with next tools, external methods, fallback actions, and memory actions",
					"Always after delegation and after each dedicated subagent tool round.",
				),
			]
		: [];
	const approvalPlan = step.requiresUserApprovalBeforeStart
		? [
				toolPlan(
					"security_user_approval",
					"Show a Codex-style selectable confirmation before starting this phase.",
					true,
					["approval title", "approval message", "Approve/Reject choices"],
					"user approval decision",
					"Always before starting a gated penetration-testing phase, broadening scope, or running higher-risk security actions.",
				),
			]
		: [];
	if (
		step.requiresAuthorization &&
		!authorizationConfirmed &&
		!selected.some((plan) => plan.tool === "security_scope_status")
	) {
		return [
			...approvalPlan,
			toolPlan(
				"security_scope_status",
				"Confirm active authorization before this phase.",
				true,
				[],
				"authorization status",
				"Required because this phase is authorization-gated.",
			),
			...delegationPlan,
			...iterationPlan,
			...selected,
		];
	}
	return [...approvalPlan, ...delegationPlan, ...iterationPlan, ...selected];
}

function selectSubagentToolCalls(
	definition: SecurityDedicatedSubagentDefinition,
	evidence: string[],
	remainingCriteria: string[],
	toolErrors: string[],
	forceMemoryPersistence: boolean,
): SecurityStepToolCallPlan[] {
	const calls = definition.tools.toolCalls ?? [];
	const haystack = `${evidence.join("\n")} ${remainingCriteria.join("\n")} ${toolErrors.join("\n")}`.toLowerCase();
	const selected = calls.filter((call) => {
		if (call.required) return true;
		return (
			call.inputsNeeded.some((input) => haystack.includes(input.toLowerCase())) ||
			call.expectedOutput
				.toLowerCase()
				.split(/[^a-z0-9]+/)
				.filter((word) => word.length >= 4)
				.some((word) => haystack.includes(word)) ||
			toolErrors.some((error) => error.toLowerCase().includes(call.tool.toLowerCase()))
		);
	});
	const plans = selected.map((call) =>
		toolPlan(call.tool, call.description, call.required, call.inputsNeeded, call.expectedOutput, call.useWhen),
	);
	if (forceMemoryPersistence && !plans.some((plan) => plan.tool === "security_memory")) {
		return [
			...plans,
			toolPlan(
				"security_memory",
				"Persist final subagent evidence, handoff, limitations, and unresolved gaps before stopping or moving to the next phase.",
				true,
				["action=remember", "final handoff evidence", "source attribution", "limitations"],
				"stored memory metadata proving evidence was persisted",
				"Required when expected subagent evidence is collected but no memory persistence evidence exists yet.",
			),
		];
	}
	return plans;
}

function selectSubagentExternalMethods(
	definition: SecurityDedicatedSubagentDefinition,
	evidence: string[],
	remainingCriteria: string[],
	toolErrors: string[],
): SecurityExternalToolPrompt[] {
	const calls = definition.tools.externalToolCalls ?? [];
	const haystack = `${evidence.join("\n")} ${remainingCriteria.join("\n")} ${toolErrors.join("\n")}`.toLowerCase();
	return calls
		.filter((call) => {
			if (call.required) return true;
			return (
				call.inputsNeeded.some((input) => haystack.includes(input.toLowerCase())) ||
				call.expectedOutput
					.toLowerCase()
					.split(/[^a-z0-9]+/)
					.filter((word) => word.length >= 4)
					.some((word) => haystack.includes(word)) ||
				toolErrors.some((error) => error.toLowerCase().includes(call.method.toLowerCase()))
			);
		})
		.map((call) => ({
			tool: call.method,
			prompt: call.prompt,
			useWhen: call.useWhen,
			safetyConstraints: call.safetyConstraints,
		}));
}

function buildSubagentFallbackActions(
	definition: SecurityDedicatedSubagentDefinition,
	toolErrors: string[],
	remainingCriteria: string[],
): string[] {
	const actions = [
		"Retry with a narrower query, fewer targets, lower rate, or imported output when the previous tool failed transiently.",
		"Switch from a failed built-in tool to the matching externalToolCalls method when it is authorized and safer.",
		"Switch from a failed external method to built-in corroboration, cached prior results, or customer-provided inventory.",
		"Record failed attempts, error messages, limitations, and unresolved gaps in security_memory.",
	];
	if (toolErrors.length > 0) {
		actions.push(`Review tool error(s) before the next attempt: ${toolErrors.slice(0, 3).join("; ")}`);
	}
	if (remainingCriteria.length > 0) {
		actions.push(
			`Prioritize unresolved ${definition.displayName} criteria: ${remainingCriteria.slice(0, 5).join("; ")}`,
		);
	}
	actions.push(
		"If fallback still cannot collect the expected evidence, request manual intervention with clear choices.",
	);
	return actions;
}

function buildOperatorChoicePrompt(
	definition: SecurityDedicatedSubagentDefinition,
	objective: string,
	targets: string[],
	decision: SecuritySubagentIterationDecision,
	toolErrors: string[],
	remainingCriteria: string[],
): SecurityApprovalPrompt {
	const baseOptions =
		decision === "complete"
			? ["Proceed to next phase", "Collect more evidence", "Review handoff first"]
			: decision === "manual_intervention"
				? ["Provide missing data", "Approve alternate method", "Skip with limitations", "Stop phase"]
				: ["Continue collecting", "Provide missing data", "Approve alternate method", "Skip with limitations"];
	const options = withManualSuggestionOption(baseOptions);
	return {
		title: `Choose next action for ${definition.displayName}`,
		message: [
			`Objective: ${objective}`,
			targets.length > 0 ? `Targets: ${targets.join(", ")}` : "Targets: not confirmed",
			`Planner decision: ${decision}`,
			toolErrors.length > 0 ? `Tool errors: ${toolErrors.slice(0, 3).join("; ")}` : "Tool errors: none reported",
			`Remaining criteria: ${remainingCriteria.length > 0 ? remainingCriteria.slice(0, 6).join("; ") : "none"}`,
			"Use the selector so the human operator can decide whether this subagent should continue, use alternate inputs, skip with documented limitations, or proceed.",
			"Select 人工建议 or use Tab/input-capable UI to provide operator guidance; feed that text into the next security_subagent_iteration_plan call as manual input for replanning or generation.",
		].join("\n"),
		options,
		defaultOption: options[0] ?? "Continue collecting",
		requiredBefore: "phase_start",
	};
}

function buildSubagentMemoryActions(
	definition: SecurityDedicatedSubagentDefinition,
	decision: SecuritySubagentIterationDecision,
): string[] {
	const actions = [
		"Use security_memory action=remember for useful evidence, source attribution, limitations, and unresolved gaps.",
	];
	if (decision === "complete") {
		actions.push(`Persist the final ${definition.displayName} handoff before moving to the next phase.`);
	}
	if (decision === "manual_intervention") {
		actions.push(`Persist failed attempts and the manual decision needed for ${definition.displayName}.`);
	}
	return actions;
}

function hasMemoryPersistenceEvidence(evidence: string[]): boolean {
	const haystack = evidence.join("\n").toLowerCase();
	return (
		haystack.includes("security_memory") ||
		haystack.includes("memory stored") ||
		haystack.includes("memory persisted") ||
		haystack.includes("stored memory metadata") ||
		haystack.includes("action=remember") ||
		haystack.includes("remembered")
	);
}

function buildApprovalPrompt(step: SecurityWorkflowStep, objective: string, targets: string[]): SecurityApprovalPrompt {
	const targetText = targets.length > 0 ? targets.join(", ") : "target must be confirmed";
	const requiredBefore =
		step.phase === "clarify"
			? "authorization_scope"
			: step.phase === "exploitation" || step.phase === "privilege_escalation"
				? "dangerous_action"
				: "phase_start";
	return {
		title: `Approve ${step.phase.replaceAll("_", " ")}`,
		message: [
			`Objective: ${objective}`,
			`Targets: ${targetText}`,
			`Step: ${step.objective}`,
			"Use the selector: Enter approves the highlighted choice; Up/Down changes the choice; select 人工建议 or use Tab/input-capable UI to type guidance for replanning.",
		].join("\n"),
		options: withManualSuggestionOption(
			requiredBefore === "phase_start"
				? ["Approve", "Approve all next-phase requests this session", "Reject"]
				: ["Approve", "Reject"],
		),
		defaultOption: "Approve",
		requiredBefore,
	};
}

function withManualSuggestionOption(options: string[]): string[] {
	return options.includes(MANUAL_SUGGESTION_OPTION) ? options : [...options, MANUAL_SUGGESTION_OPTION];
}

function renderStepPrompt(
	step: SecurityWorkflowStep,
	objective: string,
	targets: string[],
	priorResults: string[],
	missingInformation: string[],
): string {
	return [
		`Phase: ${step.phase}`,
		step.dedicatedSubagent
			? `Dedicated subagent: ${getSecurityDedicatedSubagentDefinition(step.dedicatedSubagent).displayName}`
			: "Dedicated subagent: none",
		`Objective: ${objective}`,
		targets.length > 0 ? `Targets: ${targets.join(", ")}` : "Targets: recover or ask for explicit targets.",
		step.stepPrompt,
		`Required information: ${step.requiredInformation.join("; ")}`,
		`Missing information to collect now: ${missingInformation.length > 0 ? missingInformation.join("; ") : "none detected"}`,
		priorResults.length > 0
			? `Prior results to use: ${priorResults.slice(0, 8).join("; ")}`
			: "Prior results to use: none supplied; collect fresh evidence with the selected tools.",
		step.dedicatedSubagent
			? "Selected tool rule: call security_step_execution_plan first, then call security_delegate_subagent and security_subagent_iteration_plan before any phase evidence tools; re-run the iteration plan after each tool round until it returns complete or manual_intervention."
			: "Selected tool rule: call security_step_execution_plan first for this phase, then call each required selected tool before summarizing the phase.",
	].join("\n");
}

function buildNextDecisionInputs(step: SecurityWorkflowStep): string[] {
	const common = ["evidence collected", "missing information", "limitations", "recommended next phase"];
	if (step.reportAfterStep) {
		return [...common, "saved report paths", "findings summary"];
	}
	return common;
}

function hasEvidenceFor(information: string, priorResults: string[]): boolean {
	const words = information
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.filter((word) => word.length >= 4);
	if (words.length === 0) return false;
	const haystack = priorResults.join("\n").toLowerCase();
	return words.some((word) => haystack.includes(word));
}

function normalizeTexts(values: string[]): string[] {
	return values.map((value) => value.trim()).filter(Boolean);
}

function mergeUnique(values: string[]): string[] {
	return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
