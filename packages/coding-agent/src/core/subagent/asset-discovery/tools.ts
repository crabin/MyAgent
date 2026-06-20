import type {
	SecurityDedicatedSubagentExternalToolCall,
	SecurityDedicatedSubagentToolCall,
	SecurityDedicatedSubagentToolContract,
} from "../types.ts";

const sharedAssetSafetyConstraints = [
	"Stay inside the explicit authorization scope and do not expand targets without user approval.",
	"Treat passive OSINT and third-party platform results as untrusted until corroborated.",
	"Do not collect credentials, secrets, personal data, or private repository content.",
	"Do not perform active network discovery until security_scope_status confirms the target is authorized.",
];

export const ASSET_DISCOVERY_BUILT_IN_TOOL_CALLS: SecurityDedicatedSubagentToolCall[] = [
	{
		tool: "security_scope_status",
		label: "Security Scope Status",
		description: "Inspect the active in-session authorization scope before any target-touching asset discovery.",
		required: true,
		promptSnippet: "Check the active authorization scope before asset discovery.",
		promptGuidelines: [
			"Call this first in the asset discovery phase.",
			"Use the returned authorized targets, allowed actions, expiry, and gaps to decide whether discovery can proceed.",
			"If no active scope exists, stop active discovery and request explicit targets, allowed actions, and duration.",
		],
		parameters: [],
		inputsNeeded: ["current session authorization state"],
		expectedOutput:
			"authorization status, authorized targets, allowed actions, expiry, and missing authorization gaps",
		useWhen: "Always at the start of asset discovery and again before any active discovery or scope expansion.",
		safetyConstraints: sharedAssetSafetyConstraints,
		nextStepUse: "Gate all subsequent passive and active asset discovery decisions.",
	},
	{
		tool: "security_memory",
		label: "Security Memory",
		description: "Recall and store asset inventory context, exclusions, source attribution, and discovery gaps.",
		required: true,
		promptSnippet: "Recall previous asset inventory and persist the current asset discovery handoff.",
		promptGuidelines: [
			"Call action=recall or action=context before collecting new data when this looks like a continuation.",
			"Store the final asset inventory, exclusions, sources, and gaps with action=remember.",
			"Do not store credentials, secrets, private personal data, or exploit payloads.",
		],
		parameters: [
			{
				name: "action",
				required: true,
				description: "Use recall/context before discovery and remember after producing the asset inventory.",
				source: "asset discovery phase state",
			},
			{
				name: "query",
				required: false,
				description: "Target, domain, organization, or prior assessment identifier to recall.",
				source: "user objective or target scope",
			},
			{
				name: "content",
				required: false,
				description: "Final inventory, source attribution, exclusions, or gaps to store.",
				source: "completed asset discovery results",
			},
		],
		inputsNeeded: ["target or organization query", "asset inventory summary to persist"],
		expectedOutput: "recalled context or stored memory metadata",
		useWhen: "Use before continuing previous asset discovery and after producing handoff output.",
		safetyConstraints: sharedAssetSafetyConstraints,
		nextStepUse: "Avoid duplicate collection and provide continuity for attack surface analysis.",
	},
	{
		tool: "security_research",
		label: "Security Research",
		description:
			"Perform passive public information exploration for asset clues, source evidence, and coverage gaps.",
		required: false,
		promptSnippet: "Research public asset clues before active validation.",
		promptGuidelines: [
			"Use this after choosing relevant external methods for a domain, URL, organization, product page, or visible target clue.",
			"Merge public web search, page extraction, bounded crawl, and passive metadata observations into one research pass.",
			"Use include_crawl=false unless a small same-domain crawl is specifically useful and in scope.",
			"Do not treat research output as authorization for active scanning.",
		],
		parameters: [
			{
				name: "query",
				required: true,
				description: "Domain, URL, organization, IP, cloud asset clue, or asset discovery question.",
				source: "authorized targets or user-supplied asset inventory",
			},
			{
				name: "target_url",
				required: false,
				description: "HTTP/HTTPS URL when page extraction or DNS/API metadata is useful.",
				source: "authorized URL target",
			},
			{
				name: "include_search",
				required: false,
				description: "Enable passive web search for public asset evidence.",
				source: "default true for domains and organizations",
			},
			{
				name: "include_api",
				required: false,
				description: "Enable passive DNS/API metadata during the public research pass.",
				source: "default true when target_url is provided",
			},
		],
		inputsNeeded: ["authorized target", "organization or domain context"],
		expectedOutput: "passive observations, candidate assets, source URLs, DNS/API metadata, and evidence gaps",
		useWhen:
			"Use when public information exploration is needed to corroborate candidate assets or identify coverage gaps.",
		safetyConstraints: sharedAssetSafetyConstraints,
		nextStepUse: "Feed public findings into api_client only when structured metadata lookup or parsing is needed.",
	},
	{
		tool: "api_client",
		label: "API Client",
		description: "Perform structured metadata/API queries and normalize machine-readable asset evidence.",
		required: false,
		promptSnippet: "Query and normalize structured DNS/IP/GitHub/API metadata for candidate assets.",
		promptGuidelines: [
			"Use preset=dns_resolve for domain-to-address context.",
			"Use preset=ip_info for IP ownership and network context.",
			"Use GitHub presets only for public repository or user metadata relevant to asset exposure.",
			"Use this after security_research or external methods identify a structured lookup target.",
			"Do not send credentials, private tokens, exploit payloads, or destructive methods.",
		],
		parameters: [
			{
				name: "preset",
				required: false,
				description: "dns_resolve, ip_info, github_repo, or github_user when a preset fits the asset question.",
				source: "target type and missing information",
			},
			{
				name: "query",
				required: false,
				description: "Domain, IP, GitHub repository, or GitHub user.",
				source: "candidate asset or OSINT clue",
			},
			{
				name: "url",
				required: false,
				description: "Read-only metadata API URL when no preset fits.",
				source: "approved public metadata source",
			},
		],
		inputsNeeded: ["domain, IP, repo, user, or metadata URL"],
		expectedOutput: "DNS answers, IP ownership/network metadata, public GitHub metadata, or metadata API response",
		useWhen:
			"Use when asset discovery needs structured DNS resolution, IP metadata, public code metadata, or API response normalization.",
		safetyConstraints: sharedAssetSafetyConstraints,
		nextStepUse:
			"Normalize candidate assets and decide whether network discovery or attack surface mapping is warranted.",
	},
	{
		tool: "security_report",
		label: "Security Report",
		description:
			"Assemble the asset discovery inventory, methodology, limitations, and handoff into a report artifact.",
		required: false,
		promptSnippet: "Generate an asset discovery report when the user requested deliverables or phase handoff.",
		promptGuidelines: [
			"Use this after evidence collection when the user requested a report or when a durable handoff is needed.",
			"Include scope, methods, sources, limitations, and confidence.",
			"Do not claim validation for assets that were only observed in uncorroborated passive results.",
		],
		parameters: [
			{
				name: "scope",
				required: true,
				description: "Authorized targets covered by asset discovery.",
				source: "security_scope_status and user authorization",
			},
			{
				name: "methodology",
				required: false,
				description: "Tools and external methods used.",
				source: "completed asset discovery tool calls",
			},
			{
				name: "findings",
				required: false,
				description: "Asset inventory entries, open services, and coverage gaps as report findings.",
				source: "asset discovery results",
			},
			{
				name: "save_to_reports",
				required: false,
				description: "Save report files under reports/ when a durable artifact is needed.",
				source: "user report request or phase requirement",
			},
		],
		inputsNeeded: ["scope", "asset inventory", "methodology", "limitations"],
		expectedOutput: "Markdown/JSON asset discovery report content or saved paths",
		useWhen: "Use when the user asked for a report or before handing off a completed asset inventory.",
		safetyConstraints: sharedAssetSafetyConstraints,
		nextStepUse: "Provide durable evidence for attack surface analysis and later reporting.",
	},
];
export const ASSET_DISCOVERY_EXTERNAL_TOOL_CALLS: SecurityDedicatedSubagentExternalToolCall[] = [
	{
		method: "Customer-provided asset inventory",
		category: "user_supplied",
		required: true,
		inputsNeeded: [
			"authorized scope file, asset list, ticket, CMDB export, cloud inventory, exclusions, owners, test window",
		],
		expectedOutput:
			"authoritative baseline assets, exclusions, owners, approved discovery boundaries, confidence level",
		useWhen: "Always start from customer-provided authoritative scope before public or active discovery.",
		prompt:
			"Ask for authoritative scope, exclusions, owners, test window, allowed discovery depth, and approved port/protocol scope. Normalize this as the source-of-truth baseline.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Domain ownership and registration lookup",
		category: "passive_osint",
		required: false,
		inputsNeeded: ["domain, organization name, IP, ASN, or netblock"],
		expectedOutput:
			"RDAP/Whois metadata, registrar, nameservers, registration clues, ASN/netblock hints, ownership caveats",
		useWhen: "Use when domain, organization, IP, or network ownership needs passive validation.",
		prompt:
			"Use RDAP/Whois/ASN data to propose ownership and relationship hints. Treat registrant data as privacy-sensitive and low-to-medium confidence unless corroborated.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "DNS and certificate transparency enumeration",
		category: "passive_osint",
		required: true,
		inputsNeeded: ["authorized root domain", "approved DNS record types"],
		expectedOutput:
			"A/AAAA/CNAME/MX/NS/TXT records, CT hostnames, wildcard findings, candidate subdomains, source and confidence",
		useWhen: "Use for every authorized root domain before active validation.",
		prompt:
			"Collect DNS records and certificate transparency names, including crt.sh-like CT sources. Normalize wildcards, deduplicate, resolve candidates, and record source confidence.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Passive subdomain enumeration",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: ["authorized root domain", "reviewed command", "rate limits", "API keys if available"],
		expectedOutput: "candidate subdomains with source metadata and confidence",
		useWhen: "Use when broad passive subdomain coverage is needed.",
		prompt:
			"Prefer Subfinder for fast passive enumeration. Use only authorized root domains. Deduplicate and import results with source attribution.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Attack surface relationship mapping",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"authorized root domain, organization, ASN, or netblock",
			"passive/active mode decision",
			"reviewed command",
		],
		expectedOutput: "related domains, subdomains, ASNs, netblocks, relationships, and source metadata",
		useWhen:
			"Use Amass when relationship mapping, ASN/netblock correlation, or broader attack-surface context is needed.",
		prompt:
			"Prefer passive Amass mode by default. Require explicit approval for active enumeration, brute forcing, alterations, or recursive active techniques.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "DNS resolution validation",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: ["candidate hostnames", "approved resolver strategy", "rate limits"],
		expectedOutput: "resolved hosts, IP mappings, CNAME chains, wildcard filtering, resolution confidence",
		useWhen: "Use after passive subdomain collection to remove dead, wildcard, or duplicate candidates.",
		prompt:
			"Resolve candidate hostnames using bounded DNS queries. Detect wildcard DNS and preserve hostname-to-IP relationships.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "HTTP service probing",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: ["authorized hostnames or IPs", "approved ports or default web ports", "rate limits"],
		expectedOutput: "live HTTP/HTTPS services, status codes, titles, redirects, technologies, TLS metadata",
		useWhen: "Use when web-facing asset validation is needed before heavier scanning.",
		prompt:
			"Probe only authorized targets using bounded HTTP checks. Record evidence as service observations, not vulnerabilities.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},
	{
		method: "Technology fingerprinting",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"authorized HTTP endpoints or service banners",
			"reviewed WhatWeb, Wappalyzer, httpx tech-detect, or Nmap service/version output",
			"rate limits and confidence threshold",
		],
		expectedOutput:
			"server, framework, CMS, CDN/WAF, language, package, plugin, and product/version hints with source and confidence",
		useWhen:
			"Use during asset discovery when service ownership, platform grouping, or downstream attack-surface prioritization depends on technology identity.",
		prompt:
			"Prefer WhatWeb, Wappalyzer, httpx -tech-detect, or imported Nmap -sV evidence for authorized endpoints. Record fingerprint confidence and source; do not treat a fingerprint as vulnerability proof.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},
	{
		method: "Path and content discovery",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"authorized HTTP endpoint",
			"approved wordlist or imported dirsearch/ffuf/gobuster output",
			"bounded rate, filters, recursion choice, and stop conditions",
		],
		expectedOutput:
			"candidate paths, files, directories, admin panels, documentation endpoints, status codes, content lengths, redirects, and false-positive filters",
		useWhen:
			"Use when the asset inventory must include reachable web paths or documentation endpoints and passive/crawl sources leave gaps.",
		prompt:
			"Use Dirsearch, FFUF, or Gobuster only against authorized endpoints with non-destructive wordlists, bounded rate, status/size filters, and no credential or sensitive-data brute forcing.",
		safetyConstraints: [
			...sharedAssetSafetyConstraints,
			"Require explicit approval for path brute forcing, vhost brute forcing, recursion, high-rate requests, or large wordlists.",
			"Do not brute force credentials, tokens, private data, upload paths with writes, or destructive methods.",
		],
	},
	{
		method: "Virtual host discovery",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"authorized IP, hostname, or HTTP service",
			"approved vhost wordlist or imported ffuf/gobuster vhost output",
			"host-header scope, rate limits, and false-positive baseline",
		],
		expectedOutput:
			"candidate virtual hosts, response differences, status codes, titles, content lengths, and scope caveats",
		useWhen:
			"Use when shared infrastructure, wildcard DNS, or IP-only HTTP services may hide authorized virtual hosts.",
		prompt:
			"Use FFUF or Gobuster vhost mode only for authorized hosts/IPs. Baseline wildcard responses, keep request rates bounded, and do not add discovered sibling domains to scope without user approval.",
		safetyConstraints: [
			...sharedAssetSafetyConstraints,
			"Do not treat discovered virtual hosts as authorized unless they match the explicit scope or the user approves scope expansion.",
		],
	},
	{
		method: "Robots and sitemap discovery",
		category: "passive_osint",
		required: false,
		inputsNeeded: ["authorized base URL", "robots.txt, sitemap.xml, or known metadata URLs"],
		expectedOutput:
			"robots directives, sitemap URLs, documented paths, API/documentation hints, last-modified clues, and source URLs",
		useWhen:
			"Use before active path discovery to collect low-noise route and metadata hints from public web metadata.",
		prompt:
			"Fetch robots.txt, sitemap.xml, and linked public sitemaps as read-only metadata. Treat disallowed paths as clues only, not permission to access private content.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Internet exposure index search",
		category: "external_platform",
		required: false,
		inputsNeeded: [
			"domain, hostname, IP, netblock, certificate subject, organization query, available API credentials",
		],
		expectedOutput: "indexed hosts, ports, banners, certificates, timestamps, provider/source metadata",
		useWhen:
			"Use Shodan, Censys, SecurityTrails, FOFA, ZoomEye, or similar indexes when passive exposure context can improve coverage.",
		prompt:
			"Query approved external exposure indexes. Do not expose API keys. Mark all indexed data as externally observed and timestamp-dependent until validated.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Public code and documentation search",
		category: "passive_osint",
		required: false,
		inputsNeeded: ["organization, domain, repository, package, product name, public search terms"],
		expectedOutput:
			"public repos, documentation URLs, deployment clues, domains, API hostnames, non-secret config references",
		useWhen: "Use when public code/docs may reveal asset references or deployment endpoints.",
		prompt:
			"Search only public sources. Do not collect, print, store, or validate secrets. Record only asset references and context.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Cloud asset inventory import",
		category: "cloud_inventory",
		required: false,
		inputsNeeded: ["cloud inventory export or explicitly approved read-only cloud command output"],
		expectedOutput:
			"cloud resources, public IPs, load balancers, storage endpoints, DNS zones, account/project context",
		useWhen: "Use when the user supplies cloud inventory or explicitly authorizes read-only cloud enumeration.",
		prompt:
			"Prefer imported cloud inventory exports. If commands are needed, require explicit read-only approval and never store credentials.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Reverse IP and virtual-host correlation",
		category: "passive_osint",
		required: false,
		inputsNeeded: ["authorized IP address, hostname, or netblock"],
		expectedOutput: "co-hosted domains, virtual-host hints, shared hosting caveats, relationship confidence",
		useWhen:
			"Use when IP-based correlation may reveal related assets, especially shared hosting or CDN-backed services.",
		prompt:
			"Use reverse-IP and virtual-host data cautiously. Do not treat co-hosted domains as in scope without explicit authorization.",
		safetyConstraints: sharedAssetSafetyConstraints,
	},

	{
		method: "Nmap",
		category: "authorized_terminal",
		required: false,
		inputsNeeded: [
			"active authorization scope",
			"authorized host, IP, URL, or CIDR target",
			"reviewed command; default TCP port scope is 1-65535 unless the user narrows it",
			"rate limits, timing constraints, and long-running execution strategy",
		],
		expectedOutput:
			"full TCP 1-65535 port coverage by default, live hosts, open ports, likely services, scan timing, command summary, and limitations",
		useWhen:
			"Use when the asset discovery objective includes port/service detection; default to full TCP 1-65535 for authorized asset discovery port scans unless the user narrows scope or provides Nmap output to import.",
		prompt:
			"Prepare or ingest a reviewed, bounded Nmap command only for authorized targets; default TCP port scan scope is all ports (-p 1-65535) for asset discovery unless the user narrows it, prefer importing existing Nmap output when available, run full-port scans with security_terminal_session action=start plus action=read polling or an explicit long timeout instead of a short 120s wait, and record open ports as observations rather than vulnerability proof.",
		safetyConstraints: [
			...sharedAssetSafetyConstraints,
			"Require security_scope_status to confirm every target before running Nmap.",
			"Treat full TCP 1-65535 as the default asset-discovery Nmap port scope after the user authorizes asset/port scanning for the target.",
			"For full TCP Nmap scans, wait for natural completion with an explicit long timeout or run asynchronously and poll output; do not assume 120s is enough.",
			"Require explicit user approval before UDP scans, aggressive timing, version detection, OS detection, NSE scripts, or scope expansion.",
			"Do not use NSE scripts that attempt exploitation, brute force, credential access, denial of service, or intrusive behavior.",
			"Keep rate, timing, host count, and port range bounded to the approved test window.",
		],
	},
];

export const ASSET_DISCOVERY_TOOLS: SecurityDedicatedSubagentToolContract = {
	requiredTools: ASSET_DISCOVERY_BUILT_IN_TOOL_CALLS.filter((tool) => tool.required).map((tool) => tool.tool),
	optionalTools: ASSET_DISCOVERY_BUILT_IN_TOOL_CALLS.filter((tool) => !tool.required).map((tool) => tool.tool),
	externalMethods: ASSET_DISCOVERY_EXTERNAL_TOOL_CALLS.map((tool) => tool.method),
	toolCalls: ASSET_DISCOVERY_BUILT_IN_TOOL_CALLS,
	externalToolCalls: ASSET_DISCOVERY_EXTERNAL_TOOL_CALLS,
};
