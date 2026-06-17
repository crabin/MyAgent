import { describe, expect, it } from "vitest";
import { BUILTIN_SLASH_COMMANDS } from "../src/core/slash-commands.ts";

describe("built-in slash commands", () => {
	it("includes a command to clear secbot memory without starting a new session", () => {
		expect(BUILTIN_SLASH_COMMANDS).toContainEqual({
			name: "clear-secbot",
			description: "Clear secbot memory for the current session directory",
		});
	});
});
