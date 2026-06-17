export type SecurityFindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface SecurityFindingInput {
	title: string;
	severity?: SecurityFindingSeverity;
	asset?: string;
	evidence?: string;
	impact?: string;
	remediation?: string;
	references?: string[];
}

export interface SecurityReportInput {
	title?: string;
	scope: string[];
	methodology?: string[];
	findings?: SecurityFindingInput[];
	limitations?: string[];
	generatedAt?: Date;
}

export interface SecurityReport {
	title: string;
	generatedAt: string;
	scope: string[];
	methodology: string[];
	findings: Required<SecurityFindingInput>[];
	limitations: string[];
	summary: {
		totalFindings: number;
		bySeverity: Record<SecurityFindingSeverity, number>;
	};
	markdown: string;
}

const SEVERITIES: SecurityFindingSeverity[] = ["critical", "high", "medium", "low", "info"];

export function assembleSecurityReport(input: SecurityReportInput): SecurityReport {
	const title = normalizeText(input.title, "Security Assessment Report");
	const generatedAt = (input.generatedAt ?? new Date()).toISOString();
	const scope = normalizeList(input.scope);
	if (scope.length === 0) {
		throw new Error("Report scope must include at least one target or asset.");
	}
	const methodology = normalizeList(input.methodology ?? ["Read-only research", "Evidence review", "Risk analysis"]);
	const limitations = normalizeList(input.limitations ?? ["No exploitation was performed by this report generator."]);
	const findings = normalizeFindings(input.findings ?? []);
	const summary = summarizeFindings(findings);
	const markdown = renderMarkdown({ title, generatedAt, scope, methodology, findings, limitations, summary });

	return { title, generatedAt, scope, methodology, findings, limitations, summary, markdown };
}

function normalizeFindings(findings: SecurityFindingInput[]): Required<SecurityFindingInput>[] {
	return findings.map((finding) => ({
		title: normalizeText(finding.title, "Untitled finding"),
		severity: finding.severity ?? "info",
		asset: normalizeText(finding.asset, "Not specified"),
		evidence: normalizeText(finding.evidence, "Not provided"),
		impact: normalizeText(finding.impact, "Not assessed"),
		remediation: normalizeText(finding.remediation, "Review and remediate according to vendor guidance."),
		references: normalizeList(finding.references ?? []),
	}));
}

function summarizeFindings(findings: Required<SecurityFindingInput>[]): SecurityReport["summary"] {
	const bySeverity = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<
		SecurityFindingSeverity,
		number
	>;
	for (const finding of findings) {
		bySeverity[finding.severity] += 1;
	}
	return { totalFindings: findings.length, bySeverity };
}

function renderMarkdown(report: Omit<SecurityReport, "markdown">): string {
	const lines = [
		`# ${report.title}`,
		"",
		`Generated: ${report.generatedAt}`,
		"",
		"## Executive Summary",
		"",
		`Total findings: ${report.summary.totalFindings}`,
		...SEVERITIES.map((severity) => `- ${capitalize(severity)}: ${report.summary.bySeverity[severity]}`),
		"",
		"## Scope",
		"",
		...report.scope.map((target) => `- ${target}`),
		"",
		"## Methodology",
		"",
		...report.methodology.map((step) => `- ${step}`),
		"",
		"## Findings",
		"",
	];

	if (report.findings.length === 0) {
		lines.push("No findings were provided.", "");
	} else {
		for (const finding of report.findings) {
			lines.push(
				`### ${finding.title}`,
				"",
				`Severity: ${capitalize(finding.severity)}`,
				`Asset: ${finding.asset}`,
				"",
				"Evidence:",
				finding.evidence,
				"",
				"Impact:",
				finding.impact,
				"",
				"Remediation:",
				finding.remediation,
				"",
			);
			if (finding.references.length > 0) {
				lines.push("References:", ...finding.references.map((reference) => `- ${reference}`), "");
			}
		}
	}

	lines.push("## Limitations", "", ...report.limitations.map((limitation) => `- ${limitation}`));
	return lines.join("\n");
}

function normalizeText(value: string | undefined, fallback: string): string {
	const trimmed = value?.trim();
	return trimmed && trimmed.length > 0 ? trimmed : fallback;
}

function normalizeList(values: string[]): string[] {
	return values.map((value) => value.trim()).filter((value) => value.length > 0);
}

function capitalize(value: string): string {
	return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}
