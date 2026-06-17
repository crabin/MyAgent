export interface SecurityAuthorizationScope {
	targets: string[];
	allowedActions: string[];
	reason: string;
	expiresAt?: string;
	createdAt: string;
}

export interface SecurityAuthorizationStatus {
	authorized: boolean;
	scope: SecurityAuthorizationScope | null;
}

export interface AuthorizeSecurityScopeInput {
	targets: string[];
	allowedActions?: string[];
	reason?: string;
	expiresAt?: string;
	now?: Date;
}

export interface SecurityAuthorizationStore {
	authorize(input: AuthorizeSecurityScopeInput): SecurityAuthorizationStatus;
	status(now?: Date): SecurityAuthorizationStatus;
	isTargetAuthorized(target: string, now?: Date): boolean;
	clear(): SecurityAuthorizationStatus;
}

const DEFAULT_ALLOWED_ACTIONS = ["read_only_research", "metadata_lookup", "bounded_active_scan"];

export function createSecurityAuthorizationStore(): SecurityAuthorizationStore {
	let scope: SecurityAuthorizationScope | null = null;

	return {
		authorize(input) {
			const now = input.now ?? new Date();
			const targets = normalizeList(input.targets);
			if (targets.length === 0) {
				throw new Error("At least one authorized target is required.");
			}
			const allowedActions = normalizeList(input.allowedActions ?? DEFAULT_ALLOWED_ACTIONS);
			scope = {
				targets,
				allowedActions,
				reason: normalizeReason(input.reason),
				expiresAt: normalizeExpiresAt(input.expiresAt, now),
				createdAt: now.toISOString(),
			};
			return { authorized: true, scope };
		},
		status(now = new Date()) {
			if (!scope || isExpired(scope, now)) {
				if (scope && isExpired(scope, now)) {
					scope = null;
				}
				return { authorized: false, scope: null };
			}
			return { authorized: true, scope };
		},
		isTargetAuthorized(target, now = new Date()) {
			const current = this.status(now).scope;
			if (!current) return false;
			const normalizedTarget = normalizeTarget(target);
			return current.targets.some((authorizedTarget) => targetMatches(authorizedTarget, normalizedTarget));
		},
		clear() {
			scope = null;
			return { authorized: false, scope: null };
		},
	};
}

function normalizeList(values: string[]): string[] {
	return [...new Set(values.map((value) => normalizeTarget(value)).filter((value) => value.length > 0))];
}

function normalizeReason(reason: string | undefined): string {
	const trimmed = reason?.trim();
	return trimmed && trimmed.length > 0 ? trimmed : "User explicitly authorized this defensive security scope.";
}

function normalizeExpiresAt(expiresAt: string | undefined, now: Date): string {
	if (!expiresAt) {
		return new Date(now.getTime() + 60 * 60 * 1000).toISOString();
	}
	const parsed = new Date(expiresAt);
	if (Number.isNaN(parsed.getTime())) {
		throw new Error("expires_at must be a valid ISO date string.");
	}
	if (parsed.getTime() <= now.getTime()) {
		throw new Error("expires_at must be in the future.");
	}
	return parsed.toISOString();
}

function isExpired(scope: SecurityAuthorizationScope, now: Date): boolean {
	if (!scope.expiresAt) return false;
	return new Date(scope.expiresAt).getTime() <= now.getTime();
}

function normalizeTarget(target: string): string {
	const trimmed = target.trim().toLowerCase();
	if (!trimmed) return "";
	try {
		const parsed = new URL(trimmed);
		return parsed.hostname;
	} catch {
		return trimmed.replace(/\/+$/, "");
	}
}

function targetMatches(authorizedTarget: string, requestedTarget: string): boolean {
	if (authorizedTarget === requestedTarget) return true;
	return requestedTarget.endsWith(`.${authorizedTarget}`);
}
