export type SecurityIntent =
	| "not_security"
	| "security_qa"
	| "security_task_clarify"
	| "security_task_simple"
	| "security_task_complex";

export interface SecurityIntentDecision {
	intent: SecurityIntent;
	confidence: number;
	needsAuthorization: boolean;
	needsExplore: boolean;
	needsReport: boolean;
	focus: string[];
	rationale: string;
}

const SECURITY_HINTS = [
	"安全",
	"网络安全",
	"漏洞",
	"漏洞扫描",
	"扫描",
	"渗透",
	"渗透测试",
	"端口",
	"服务检测",
	"信息收集",
	"攻击面",
	"风险评估",
	"漏洞利用",
	"注入",
	"越权",
	"弱口令",
	"暴露面",
	"资产发现",
	"入侵检测",
	"安全报告",
	"security",
	"vulnerability",
	"vuln",
	"scan",
	"scanner",
	"pentest",
	"penetration test",
	"recon",
	"enumerate",
	"nmap",
	"cve",
	"ssrf",
	"xss",
	"sqli",
	"sql injection",
	"rce",
	"attack surface",
	"threat",
];

const ACTION_HINTS = [
	"扫描",
	"检测",
	"探测",
	"枚举",
	"测试",
	"分析",
	"生成报告",
	"发现",
	"收集",
	"scan",
	"detect",
	"enumerate",
	"test",
	"analyze",
	"assess",
	"report",
	"discover",
];

const HIGH_RISK_HINTS = [
	"利用",
	"漏洞利用",
	"攻击",
	"爆破",
	"破解",
	"提权",
	"持久化",
	"横向移动",
	"反弹 shell",
	"远控",
	"远程控制",
	"exploit",
	"attack",
	"brute",
	"crack",
	"privilege escalation",
	"persistence",
	"lateral movement",
	"reverse shell",
	"remote control",
];

const KNOWLEDGE_HINTS = [
	"是什么",
	"原理",
	"解释",
	"区别",
	"如何防御",
	"怎么修复",
	"what is",
	"explain",
	"mitigate",
	"remediate",
];

export function classifySecurityIntent(text: string): SecurityIntentDecision {
	const lower = text.toLowerCase().trim();
	const focus = extractFocus(lower);
	const hasSecurityHint = includesAny(lower, SECURITY_HINTS) || focus.some((item) => item.startsWith("cve-"));
	if (!hasSecurityHint) {
		return {
			intent: "not_security",
			confidence: 0.1,
			needsAuthorization: false,
			needsExplore: false,
			needsReport: false,
			focus,
			rationale: "No security-related indicator was detected.",
		};
	}

	const hasAction = includesAny(lower, ACTION_HINTS);
	const hasHighRisk = includesAny(lower, HIGH_RISK_HINTS);
	const hasKnowledgeHint = includesAny(lower, KNOWLEDGE_HINTS);
	const hasTarget = focus.some((item) => item.includes(".") || item.startsWith("http") || isIpv4(item));

	if (!hasAction && !hasHighRisk && hasKnowledgeHint) {
		return {
			intent: "security_qa",
			confidence: 0.72,
			needsAuthorization: false,
			needsExplore: focus.length > 0,
			needsReport: false,
			focus,
			rationale: "Security knowledge question without an operational action.",
		};
	}

	if ((hasAction || hasHighRisk) && !hasTarget) {
		return {
			intent: "security_task_clarify",
			confidence: 0.78,
			needsAuthorization: true,
			needsExplore: false,
			needsReport: false,
			focus,
			rationale: "Security task request is missing a concrete target or scope.",
		};
	}

	const isComplex =
		hasHighRisk ||
		includesAny(lower, ["全量", "完整", "攻击链", "工作流", "多步", "报告", "full", "workflow", "chain"]);
	return {
		intent: isComplex ? "security_task_complex" : "security_task_simple",
		confidence: hasTarget ? 0.86 : 0.68,
		needsAuthorization: true,
		needsExplore: hasTarget || focus.length > 0,
		needsReport: isComplex || includesAny(lower, ["报告", "report"]),
		focus,
		rationale: hasHighRisk
			? "Security task contains high-risk wording and must be constrained to defensive, authorized guidance."
			: "Security task contains a concrete target or operational security action.",
	};
}

function includesAny(text: string, hints: string[]): boolean {
	return hints.some((hint) => text.includes(hint));
}

function extractFocus(text: string): string[] {
	const focus = new Set<string>();
	const patterns = [
		/\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
		/\bcve-\d{4}-\d{4,7}\b/gi,
		/\bhttps?:\/\/[^\s)>"']+/gi,
		/\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi,
	];
	for (const pattern of patterns) {
		for (const match of text.matchAll(pattern)) {
			const value = match[0].replace(/[.,;:]+$/, "").toLowerCase();
			if (value) {
				focus.add(value);
			}
		}
	}
	return [...focus].slice(0, 12);
}

function isIpv4(value: string): boolean {
	const parts = value.split(".");
	return (
		parts.length === 4 &&
		parts.every((part) => {
			const n = Number(part);
			return Number.isInteger(n) && n >= 0 && n <= 255;
		})
	);
}
