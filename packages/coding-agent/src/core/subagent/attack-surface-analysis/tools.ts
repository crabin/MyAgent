import type {
	SecurityDedicatedSubagentExternalToolCall,
	SecurityDedicatedSubagentToolCall,
	SecurityDedicatedSubagentToolContract,
} from "../types.ts";

const sharedAttackSurfaceSafetyConstraints = [
	"Use only asset discovery handoff and explicitly authorized targets.",
	"Prefer reviewed external scanner output or imported results before running terminal commands.",
	"Do not execute payloads, brute force, bypass authentication, or decide PoC viability.",
	"Treat fingerprints, banners, crawls, and screenshots as evidence with confidence levels, not certainty.",
];

export const ATTACK_SURFACE_ANALYSIS_BUILT_IN_TOOL_CALLS: SecurityDedicatedSubagentToolCall[] = [
	{
		tool: "security_memory",
		label: "Security Memory",
		description: "Recall asset discovery handoff and store the final attack surface map.",
		required: true,
		promptSnippet: "Recall asset inventory before analysis and remember the final attack surface handoff.",
		promptGuidelines: [
			"Use recall/context to recover asset discovery output before selecting external methods.",
			"Store services, middleware, product/version evidence, routes, APIs, auth boundaries, and gaps.",
			"Do not store secrets, credentials, exploit payloads, or private personal data.",
		],
		parameters: [
			{
				name: "action",
				required: true,
				description: "recall/context before analysis or remember after mapping.",
				source: "phase state",
			},
			{
				name: "query",
				required: false,
				description: "Target or asset inventory query.",
				source: "asset discovery handoff",
			},
			{
				name: "content",
				required: false,
				description: "Attack surface map summary to store.",
				source: "completed analysis",
			},
		],
		inputsNeeded: ["asset discovery handoff", "target or service query"],
		expectedOutput: "recalled asset context or stored attack surface memory metadata",
		useWhen: "Use before choosing external methods and after producing the attack surface handoff.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
		nextStepUse: "Provide continuity and hand off service/middleware evidence to PoC research.",
	},
	{
		tool: "security_web_analysis",
		label: "Security Web Analysis",
		description: "Analyze authorized web pages once for headers, content metadata, links, scripts, and auth clues.",
		required: false,
		promptSnippet:
			"Use one web-analysis call per important HTTP endpoint instead of separate header/page extraction decisions.",
		promptGuidelines: [
			"Use after external methods or asset discovery identify HTTP/HTTPS endpoints.",
			"Collect title, headers, forms, links, scripts, meta, technology hints, and authentication indicators together.",
			"Treat missing headers and page clues as configuration evidence, not proof of exploitability.",
			"Keep the endpoint within the active authorization scope.",
		],
		parameters: [
			{
				name: "url",
				required: true,
				description: "Authorized HTTP or HTTPS endpoint.",
				source: "asset inventory or external method output",
			},
			{
				name: "include_page",
				required: false,
				description: "Whether to include structured page extraction. Default true.",
				source: "analysis need",
			},
		],
		inputsNeeded: ["authorized HTTP/HTTPS URL"],
		expectedOutput: "title, headers, links, scripts, metadata, technologies, forms, and authentication indicators",
		useWhen: "Use when a web endpoint needs built-in read-only corroboration after external surface discovery.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
		nextStepUse: "Feed configuration observations to the attack surface map and later PoC research.",
	},
	{
		tool: "security_crawl",
		label: "Security Crawl",
		description: "Discover routes, API hints, and JavaScript-linked URLs through a bounded read-only crawl.",
		required: false,
		promptSnippet:
			"Use crawl parameters for route/API/JS discovery instead of selecting separate small/deep crawl tools.",
		promptGuidelines: [
			"Use for route discovery, API discovery, and JavaScript link discovery.",
			"Use max_depth, max_pages, same_domain, and url_pattern to tune breadth.",
			"Use same_domain=true unless scope explicitly allows broader traversal.",
			"Do not use crawling to bypass auth, scrape sensitive data, or stress the target.",
		],
		parameters: [
			{
				name: "start_url",
				required: true,
				description: "Authorized crawl start URL.",
				source: "HTTP endpoint or external crawler output",
			},
			{ name: "max_depth", required: false, description: "Small crawl depth.", source: "approved analysis breadth" },
			{ name: "max_pages", required: false, description: "Small page cap.", source: "approved analysis breadth" },
			{
				name: "same_domain",
				required: false,
				description: "Restrict crawl to the starting domain.",
				source: "scope boundary",
			},
		],
		inputsNeeded: ["authorized start URL", "bounded crawl limits"],
		expectedOutput: "route inventory, API hints, JavaScript links, page metadata, and content previews",
		useWhen: "Use only after external route discovery or page extraction indicates bounded crawl will fill a gap.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
		nextStepUse: "Populate route/API/form entries for the attack surface map.",
	},
	{
		tool: "security_external_tool_runner",
		label: "Security External Tool Runner",
		description: "Import or run reviewed external methods after explicit authorization.",
		required: false,
		promptSnippet: "Use the external tool runner for httpx, nmap, whatweb, katana, ffuf, and related method groups.",
		promptGuidelines: [
			"Prefer importing existing external tool output when possible.",
			"Use terminal execution only for reviewed commands that implement an external method and fit authorization.",
			"Explain command purpose, target, expected output, and limits before execution.",
			"Use action=start and action=read for long-running service discovery, crawl, route discovery, or screenshot jobs.",
		],
		parameters: [
			{
				name: "action",
				required: true,
				description: "open, exec, start, read, list, or close.",
				source: "external tool workflow",
			},
			{
				name: "command",
				required: false,
				description: "Reviewed command for a selected external method.",
				source: "external method plan",
			},
			{
				name: "timeout_sec",
				required: false,
				description: "Bounded command timeout.",
				source: "approved command limits",
			},
		],
		inputsNeeded: ["active authorization", "reviewed command or scanner output path"],
		expectedOutput: "bounded command output or imported scanner observations",
		useWhen:
			"Use when an external method group such as Service Discovery, HTTP Surface Discovery, Technology Fingerprinting, Route Discovery, or Web Crawling needs execution/import.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
		nextStepUse: "Normalize external method output into services, technologies, URLs, APIs, and gaps.",
	},
	{
		tool: "api_client",
		label: "API Client",
		description:
			"Fetch read-only metadata endpoints such as robots, sitemap, OpenAPI, GraphQL docs, DNS, or IP metadata.",
		required: false,
		promptSnippet: "Inspect safe metadata endpoints discovered by external methods.",
		promptGuidelines: [
			"Use for robots.txt, sitemap.xml, OpenAPI/Swagger docs, GraphQL metadata, DNS/IP presets, or public metadata APIs.",
			"Do not send credentials, exploit payloads, or destructive methods.",
			"Prefer GET/HEAD style reads unless the user explicitly authorizes a safe request.",
		],
		parameters: [
			{ name: "preset", required: false, description: "Built-in DNS/IP/GitHub preset.", source: "metadata need" },
			{ name: "query", required: false, description: "Preset query value.", source: "asset or endpoint" },
			{
				name: "url",
				required: false,
				description: "Read-only metadata endpoint URL.",
				source: "external method output",
			},
			{
				name: "method",
				required: false,
				description: "HTTP method, usually GET.",
				source: "metadata endpoint requirement",
			},
		],
		inputsNeeded: ["metadata URL, DNS/IP query, or API docs endpoint"],
		expectedOutput: "metadata response, DNS/IP context, API documentation, or endpoint schema clues",
		useWhen: "Use after external methods identify metadata endpoints or API documentation.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
		nextStepUse: "Feed API/metadata observations into entry point and authentication boundary mapping.",
	},
	{
		tool: "security_report",
		label: "Security Report",
		description: "Assemble attack surface findings, methodology, limitations, and handoff.",
		required: false,
		promptSnippet: "Create a durable attack surface handoff when requested or before PoC research.",
		promptGuidelines: [
			"Use after external methods and built-in corroboration produce a stable surface map.",
			"Include sources, confidence, limitations, and unverified observations.",
			"Do not claim exploitability or PoC availability.",
		],
		parameters: [
			{
				name: "scope",
				required: true,
				description: "Authorized assets covered.",
				source: "asset discovery handoff",
			},
			{
				name: "methodology",
				required: false,
				description: "External and built-in methods used.",
				source: "completed analysis",
			},
			{
				name: "findings",
				required: false,
				description: "Surface map entries and gaps.",
				source: "completed analysis",
			},
			{
				name: "save_to_reports",
				required: false,
				description: "Persist report files under reports/.",
				source: "user request or phase handoff",
			},
		],
		inputsNeeded: ["scope", "attack surface map", "methodology", "limitations"],
		expectedOutput: "Markdown/JSON attack surface report content or saved paths",
		useWhen: "Use when the user wants a report or PoC research needs a durable handoff.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
		nextStepUse: "Provide report-ready surface evidence and PoC research input.",
	},
];

export const ATTACK_SURFACE_ANALYSIS_EXTERNAL_TOOL_CALLS: SecurityDedicatedSubagentExternalToolCall[] = [
	{
		method: "Service Discovery",
		category: "authorized_terminal",
		required: true,
		inputsNeeded: [
			"authorized hosts",
			"asset discovery open-port hints or approved port scope",
			"target scale",
			"reviewed command limits",
		],
		expectedOutput:
			"service reachability, open ports, protocols, banners, device hints, and version evidence where authorized",
		useWhen:
			"Use as the primary service mapping method; choose Nmap for small targets, Naabu for larger host sets, and Masscan only for explicitly authorized very large scopes.",
		prompt:
			"Import existing service-discovery output when available. Otherwise select Nmap, Naabu, or Masscan by target scale, keep commands bounded, and validate broad scan observations with safer follow-up evidence.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
	{
		method: "HTTP Surface Discovery",
		category: "authorized_terminal",
		required: true,
		inputsNeeded: ["authorized host/URL list", "reviewed command", "metadata flags"],
		expectedOutput: "HTTP services, status codes, titles, technologies, TLS metadata, and redirects",
		useWhen: "Use as a primary HTTP surface normalizer after asset discovery.",
		prompt: "Run or import httpx output for authorized hosts to normalize HTTP endpoints and metadata.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
	{
		method: "Technology Fingerprinting",
		category: "authorized_terminal",
		required: true,
		inputsNeeded: ["authorized HTTP endpoints", "WhatWeb/Wappalyzer/BuiltWith output or reviewed command"],
		expectedOutput: "CMS, frameworks, server/CDN hints, analytics, hosting, plugins, and confidence notes",
		useWhen: "Use as the primary technology fingerprint source for HTTP endpoints.",
		prompt:
			"Run/import WhatWeb for active authorized endpoints and use Wappalyzer or BuiltWith as corroborating public context; record confidence and source for each technology claim.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
	{
		method: "Visual Surface Analysis",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"authorized URL list",
			"reviewed EyeWitness/Aquatone command or imported report",
			"storage location",
		],
		expectedOutput: "screenshots, titles, response metadata, login/admin clues, and endpoint clustering",
		useWhen: "Use when many HTTP endpoints need visual triage or login/admin surface classification.",
		prompt:
			"Use EyeWitness or Aquatone only for authorized URLs; do not capture private authenticated data and record screenshot/report paths as evidence.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
	{
		method: "Route Discovery",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: ["authorized endpoint", "route/vhost/file objective", "wordlist approval", "rate limits"],
		expectedOutput:
			"candidate paths, virtual hosts, files, docs, admin paths, parameters, API paths, and status codes",
		useWhen:
			"Use when approved path, vhost, file, or content discovery is needed after passive and crawl sources leave gaps.",
		prompt:
			"Select Dirsearch, FFUF, or Gobuster by route-discovery objective. Use explicit authorization, tight filters, bounded rate, and non-destructive wordlists; avoid sensitive brute force.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
	{
		method: "Web Crawling",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: ["authorized URL", "depth/page limits", "Katana/Hakrawler command or imported output"],
		expectedOutput: "crawled URLs, forms, JavaScript links, API route hints, and endpoint graph clues",
		useWhen: "Use when crawling is authorized and endpoint graph mapping is needed.",
		prompt:
			"Select Katana for richer endpoint graph crawling or Hakrawler for lightweight link discovery. Keep depth/page bounds small and avoid authenticated private areas unless explicitly approved.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
	{
		method: "JavaScript Analysis",
		category: "authorized_terminal",
		required: true,
		inputsNeeded: ["authorized page or JS URLs", "read-only extraction method"],
		expectedOutput: "API endpoints, source maps, route names, framework clues, and configuration references",
		useWhen: "Use for modern web apps where routes and APIs are revealed through public JavaScript.",
		prompt: "Extract public JavaScript references only; do not collect secrets or use private authenticated bundles.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
	{
		method: "API & Metadata Discovery",
		category: "passive_osint",
		required: true,
		inputsNeeded: ["authorized base URL or API endpoint", "candidate metadata paths or extracted links"],
		expectedOutput:
			"robots/sitemap routes, OpenAPI/Swagger schemas, GraphQL metadata, DNS/IP context, methods, paths, and auth schemes",
		useWhen:
			"Use for authorized web endpoints before deeper crawling and whenever API documentation or metadata is discovered.",
		prompt:
			"Fetch robots.txt, sitemap.xml, public OpenAPI/Swagger docs, DNS/IP metadata, and approved GraphQL metadata as read-only evidence. Ask for explicit approval before GraphQL introspection and map auth boundaries without invoking sensitive operations.",
		safetyConstraints: sharedAttackSurfaceSafetyConstraints,
	},
];

export const ATTACK_SURFACE_ANALYSIS_TOOLS: SecurityDedicatedSubagentToolContract = {
	requiredTools: ATTACK_SURFACE_ANALYSIS_BUILT_IN_TOOL_CALLS.filter((tool) => tool.required).map((tool) => tool.tool),
	optionalTools: ATTACK_SURFACE_ANALYSIS_BUILT_IN_TOOL_CALLS.filter((tool) => !tool.required).map((tool) => tool.tool),
	externalMethods: ATTACK_SURFACE_ANALYSIS_EXTERNAL_TOOL_CALLS.map((tool) => tool.method),
	toolCalls: ATTACK_SURFACE_ANALYSIS_BUILT_IN_TOOL_CALLS,
	externalToolCalls: ATTACK_SURFACE_ANALYSIS_EXTERNAL_TOOL_CALLS,
};
