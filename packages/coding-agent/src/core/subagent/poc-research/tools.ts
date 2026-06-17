import type {
	SecurityDedicatedSubagentExternalToolCall,
	SecurityDedicatedSubagentToolCall,
	SecurityDedicatedSubagentToolContract,
} from "../types.ts";

const sharedPocResearchSafetyConstraints = [
	"Use only evidence handed off from asset discovery and attack surface analysis.",
	"Research PoC availability and defensive viability; do not execute exploits.",
	"Do not provide destructive, persistence, credential-theft, stealth, or lateral-movement instructions.",
	"Treat public PoC references as untrusted until corroborated by vulnerability records and affected-version evidence.",
];

export const POC_RESEARCH_BUILT_IN_TOOL_CALLS: SecurityDedicatedSubagentToolCall[] = [
	{
		tool: "security_scope_status",
		label: "Security Scope Status",
		description: "Check active authorization before target-bound research or scanner import/execution.",
		required: true,
		promptSnippet: "Verify authorization before using target_url research or terminal-backed scanner workflows.",
		promptGuidelines: [
			"Use before any target-bound research, scanner import workflow, or terminal session.",
			"Do not treat prior phase evidence as authorization for new targets or active scanner execution.",
			"If authorization is absent or stale, request user approval before continuing target-bound work.",
		],
		parameters: [],
		inputsNeeded: ["active authorization scope"],
		expectedOutput: "scope status and allowed targets",
		useWhen: "Always before PoC research that references live targets or terminal-backed scanner methods.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
		nextStepUse: "Gate target_url research, scanner import/execution, and report claims.",
	},
	{
		tool: "security_memory",
		label: "Security Memory",
		description: "Recall service/middleware evidence and store PoC research notes and caveats.",
		required: true,
		promptSnippet: "Recall attack surface evidence before PoC research and remember final PoC availability notes.",
		promptGuidelines: [
			"Use recall/context before selecting external sources.",
			"Store references, caveats, affected-version confidence, and report-ready findings.",
			"Do not store exploit code, secrets, or destructive instructions.",
		],
		parameters: [
			{
				name: "action",
				required: true,
				description: "recall/context before research or remember after conclusions.",
				source: "phase state",
			},
			{
				name: "query",
				required: false,
				description: "Service, middleware, product, version, or CVE query.",
				source: "attack surface handoff",
			},
			{
				name: "content",
				required: false,
				description: "PoC availability notes and caveats to store.",
				source: "completed research",
			},
		],
		inputsNeeded: ["attack surface handoff", "service/middleware query"],
		expectedOutput: "recalled service context or stored PoC research memory metadata",
		useWhen: "Use before external source selection and after producing report-ready PoC notes.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
		nextStepUse: "Preserve evidence chain for vulnerability assessment, reporting, and manual validation planning.",
	},
	{
		tool: "api_client",
		label: "API Client",
		description:
			"Query structured vulnerability metadata sources such as NVD, CVE.org, MITRE ATT&CK, GitHub advisories, and stable APIs.",
		required: true,
		promptSnippet:
			"Use structured metadata APIs before passive public research when product/version or CVE evidence exists.",
		promptGuidelines: [
			"Use for stable structured sources: NVD, CVE.org, MITRE ATT&CK, GitHub Security Advisories, and vendor/package metadata APIs.",
			"Use source/cve_id/query/limit for normalized vulnerability metadata lookup.",
			"Do not turn exploit references into execution steps.",
		],
		parameters: [
			{
				name: "source",
				required: false,
				description: "cve, nvd, exploit_db, mitre_attack, or all for structured vulnerability metadata lookup.",
				source: "structured source type",
			},
			{
				name: "cve_id",
				required: false,
				description: "Specific CVE ID.",
				source: "external source or scanner output",
			},
			{
				name: "query",
				required: false,
				description: "Product/version, GHSA ID, EDB ID, technique, package, or vulnerability keyword.",
				source: "attack surface handoff",
			},
			{ name: "limit", required: false, description: "Small result cap.", source: "research breadth" },
			{ name: "url", required: false, description: "Custom read-only metadata API URL.", source: "source plan" },
		],
		inputsNeeded: ["product/version, CVE, GHSA, package, EDB ID, technique, or structured metadata endpoint"],
		expectedOutput:
			"normalized vulnerability metadata, affected ranges, fix versions, references, and source details",
		useWhen: "Use before passive research for every observed product/version, CVE, package, or advisory ID.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
		nextStepUse: "Feed structured records into public research, assessment, and report evidence.",
	},
	{
		tool: "security_research",
		label: "Security Research",
		description:
			"Perform passive public PoC/advisory exploration with web search, page extraction, and source-context synthesis.",
		required: false,
		promptSnippet: "Use passive public research after structured metadata leaves PoC/advisory context gaps.",
		promptGuidelines: [
			"Use focused product/version/CVE/GHSA plus PoC/exploit/advisory queries.",
			"Use target_url only after security_scope_status confirms the URL is authorized and page context is necessary.",
			"Capture URLs, titles, source type, confidence, and caveats; do not copy exploit code.",
			"Use for weakly structured sources such as Exploit-DB pages, vendor advisory pages, GitHub discussions, and writeups.",
		],
		parameters: [
			{
				name: "query",
				required: true,
				description: "Focused PoC/advisory query.",
				source: "service, middleware, CVE, or external source",
			},
			{
				name: "target_url",
				required: false,
				description: "Authorized URL when target page context matters.",
				source: "attack surface map",
			},
			{
				name: "include_search",
				required: false,
				description: "Include web search. Default true.",
				source: "research need",
			},
			{
				name: "include_api",
				required: false,
				description: "Include metadata lookup. Default false here.",
				source: "research need",
			},
		],
		inputsNeeded: ["service/middleware/product/version/CVE/GHSA query", "optional authorized URL"],
		expectedOutput: "public advisory URLs, snippets, page context, possible PoC references, and evidence gaps",
		useWhen: "Use when external method output indicates missing public-reference context.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
		nextStepUse: "Corroborate candidate PoC availability and references.",
	},
	{
		tool: "security_terminal_session",
		label: "Security Terminal Session",
		description:
			"Import scanner output or run reviewed non-exploit scanner/metadata commands after explicit authorization.",
		required: false,
		promptSnippet:
			"Prefer importing external scanner output; execute only reviewed commands after scope status passes.",
		promptGuidelines: [
			"Prefer imported scanner reports and template results over running commands.",
			"Call security_scope_status before open/exec/start actions and keep commands inside active scope.",
			"Run only reviewed commands for safe scanner output import, template metadata, or local file parsing.",
			"Never execute exploit PoCs, payloads, or destructive commands.",
		],
		parameters: [
			{
				name: "action",
				required: true,
				description: "open, exec, start, read, list, or close.",
				source: "terminal workflow",
			},
			{
				name: "scanner_type",
				required: false,
				description: "network_app_scanner, supply_chain_scanner, code_scanner, or template_metadata.",
				source: "external method group",
			},
			{
				name: "command",
				required: false,
				description: "Reviewed scanner/import command.",
				source: "external method plan",
			},
			{
				name: "timeout_sec",
				required: false,
				description: "Bounded command timeout.",
				source: "approved command limits",
			},
		],
		inputsNeeded: ["active authorization", "scanner output path or reviewed non-exploit command", "scanner category"],
		expectedOutput: "imported scanner observations, template metadata, or bounded command output",
		useWhen:
			"Use when Nuclei metadata, network/app scanner output, supply-chain scanner output, or code scanner output is available or explicitly authorized.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
		nextStepUse: "Normalize scanner/template output into assessment evidence.",
	},
	{
		tool: "security_assessment",
		label: "Security Assessment",
		description: "Correlate discovery, attack surface, and PoC research evidence into defensive findings.",
		required: true,
		promptSnippet: "Convert researched vulnerability records and PoC availability notes into defensive findings.",
		promptGuidelines: [
			"Use after external methods and built-in corroboration collect enough evidence.",
			"Include limitations when version matching or PoC relevance is uncertain.",
			"Do not claim exploitation or validation was performed.",
		],
		parameters: [
			{
				name: "scope",
				required: true,
				description: "Assets covered by the supplied evidence.",
				source: "asset and attack surface handoff",
			},
			{
				name: "discovered_hosts",
				required: false,
				description: "Host/service evidence.",
				source: "attack surface handoff",
			},
			{
				name: "vulnerabilities",
				required: false,
				description: "Normalized vulnerability records.",
				source: "built-in and external source results",
			},
		],
		inputsNeeded: ["scope", "services/middleware", "vulnerability records", "PoC references and caveats"],
		expectedOutput: "severity-ranked defensive findings, evidence, remediation, references, and limitations",
		useWhen: "Use after PoC research has enough source evidence for defensive triage.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
		nextStepUse: "Feed report generation and manual validation planning.",
	},
	{
		tool: "security_report",
		label: "Security Report",
		description: "Assemble PoC research evidence, caveats, and defensive findings into report artifacts.",
		required: false,
		promptSnippet: "Generate a PoC research report or append findings to the security report.",
		promptGuidelines: [
			"Use after vulnerability assessment when the user requested a report or durable handoff.",
			"Include source URLs, confidence, affected-version caveats, and no-exploitation statement.",
			"Do not include exploit code or step-by-step attack instructions.",
		],
		parameters: [
			{ name: "scope", required: true, description: "Assets covered.", source: "asset/attack surface handoff" },
			{
				name: "methodology",
				required: false,
				description: "External and built-in sources used.",
				source: "completed research",
			},
			{
				name: "findings",
				required: false,
				description: "Report-ready defensive findings.",
				source: "vulnerability assessment",
			},
			{
				name: "save_to_reports",
				required: false,
				description: "Persist report files under reports/.",
				source: "user request or phase handoff",
			},
		],
		inputsNeeded: ["scope", "findings", "references", "limitations"],
		expectedOutput: "Markdown/JSON PoC research report content or saved paths",
		useWhen: "Use when reporting is requested or before manual validation planning.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
		nextStepUse: "Provide report-ready evidence and manual validation inputs.",
	},
];

export const POC_RESEARCH_EXTERNAL_TOOL_CALLS: SecurityDedicatedSubagentExternalToolCall[] = [
	{
		method: "NVD",
		category: "external_platform",
		required: true,
		inputsNeeded: ["CVE ID or product/version CPE clue"],
		expectedOutput: "CVSS, affected products, references, publication dates, and weakness metadata",
		useWhen: "Use as a primary authoritative vulnerability record source.",
		prompt: "Query NVD for observed products/CVEs and normalize affected versions and references.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "CVE.org",
		category: "external_platform",
		required: true,
		inputsNeeded: ["CVE ID or product keyword"],
		expectedOutput: "CVE state, descriptions, references, CNA metadata, and affected version notes",
		useWhen: "Use to corroborate official CVE details and reference URLs.",
		prompt: "Query CVE.org for official CVE metadata before accepting third-party PoC claims.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "MITRE ATT&CK",
		category: "external_platform",
		required: true,
		inputsNeeded: ["technique ID, vulnerability behavior, or attack pattern"],
		expectedOutput: "technique mappings, tactics, mitigations, and defensive context",
		useWhen: "Use when PoC availability needs defensive technique context.",
		prompt: "Map observed risk to ATT&CK technique context without adding execution guidance.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "GitHub Security Advisories",
		category: "passive_osint",
		required: true,
		inputsNeeded: ["package name, ecosystem, CVE/GHSA ID, or repository"],
		expectedOutput: "GHSA IDs, affected package ranges, patched versions, references, and ecosystem metadata",
		useWhen: "Use for package/library ecosystems and GitHub-hosted advisories.",
		prompt: "Use GitHub advisories for affected ranges and fix versions; do not collect exploit code.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "Exploit and public PoC references",
		category: "passive_osint",
		required: false,
		inputsNeeded: ["CVE ID, EDB ID, product/version, platform, exploit title, or advisory URL"],
		expectedOutput:
			"Exploit-DB/public PoC reference metadata, source URLs, verification caveats, and non-execution notes",
		useWhen: "Use to determine whether a public exploit or PoC reference exists without running it.",
		prompt:
			"Record Exploit-DB and public PoC metadata, URLs, source confidence, and caveats only; do not execute or reproduce exploit code.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "Public advisory and writeup sources",
		category: "passive_osint",
		required: false,
		inputsNeeded: ["product/version, CVE/GHSA, advisory URL, repository, or researcher writeup"],
		expectedOutput:
			"weakly structured advisory/writeup context, affected-version claims, PoC claims, caveats, and source URLs",
		useWhen: "Use when structured APIs do not explain public PoC availability or defensive relevance.",
		prompt:
			"Use security_research to collect public advisory and writeup context. Prefer primary sources, record uncertainty, and do not copy exploit code.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "Network and application scanner import",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"scanner_type such as Nessus, OpenVAS, Nikto, OWASP ZAP, Burp Suite Scanner, WPScan, or Nuclei",
			"imported scanner report or explicitly authorized scanner scope",
		],
		expectedOutput:
			"findings, plugin/template IDs, CVEs, affected hosts/URLs, evidence, confidence, and remediation text",
		useWhen: "Use when network or application scanner output is available for corroboration.",
		prompt:
			"Prefer imported scanner output. If execution is explicitly authorized, call security_scope_status first, keep scope bounded, and do not trigger exploit PoCs or intrusive checks.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "Supply-chain and code scanner import",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"scanner_type such as Trivy, Grype, Syft, Semgrep, CodeQL, Snyk, or SARIF/SBOM import",
			"authorized source tree, image, SBOM, IaC path, or imported report",
		],
		expectedOutput:
			"package vulnerabilities, affected versions, fix versions, static-analysis findings, CWE mappings, and evidence locations",
		useWhen: "Use when supply-chain, container, SBOM, IaC, or source-code evidence is supplied or in scope.",
		prompt:
			"Prefer imported SBOM/SARIF/scanner output. If execution is authorized, use read-only modes, avoid storing secrets, and summarize code evidence defensively.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
	{
		method: "Vendor advisories",
		category: "passive_osint",
		required: true,
		inputsNeeded: ["vendor, product, version, CVE, or advisory ID"],
		expectedOutput: "official affected versions, patches, mitigations, references, and exploit status notes",
		useWhen: "Use as the highest-confidence external source for product/version impact.",
		prompt: "Prioritize vendor advisory facts over third-party PoC claims.",
		safetyConstraints: sharedPocResearchSafetyConstraints,
	},
];

export const POC_RESEARCH_TOOLS: SecurityDedicatedSubagentToolContract = {
	requiredTools: POC_RESEARCH_BUILT_IN_TOOL_CALLS.filter((tool) => tool.required).map((tool) => tool.tool),
	optionalTools: POC_RESEARCH_BUILT_IN_TOOL_CALLS.filter((tool) => !tool.required).map((tool) => tool.tool),
	externalMethods: POC_RESEARCH_EXTERNAL_TOOL_CALLS.map((tool) => tool.method),
	toolCalls: POC_RESEARCH_BUILT_IN_TOOL_CALLS,
	externalToolCalls: POC_RESEARCH_EXTERNAL_TOOL_CALLS,
};
