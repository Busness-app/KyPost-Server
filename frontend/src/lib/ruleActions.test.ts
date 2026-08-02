import { describe, expect, it } from "vitest";
import { MAX_ACTIONS_PER_RULE, isVisibilityChanging, ruleActionsError } from "./ruleActions";

describe("ruleActionsError", () => {
  it("accepts the shapes the builder normally produces", () => {
    expect(ruleActionsError([])).toBe("");
    expect(ruleActionsError([{ type: "archive" }])).toBe("");
    expect(ruleActionsError([{ type: "archive" }, { type: "stop" }])).toBe("");
    expect(ruleActionsError([{ type: "keyword", value: "VIP" }, { type: "archive" }])).toBe("");
    expect(
      ruleActionsError([
        { type: "keyword", value: "VIP" },
        { type: "move", value: "Later" },
        { type: "stop" }
      ])
    ).toBe("");
  });

  // The builder's select cannot produce these, but a draft cloned from a stored
  // rule can — rules.json predates the validation and the API is not its only
  // writer. Without this the UI showed no error and enabled Save on a rule the
  // server rejects, which is the 400 this module exists to pre-empt.
  it("rejects action types the server cannot run", () => {
    expect(ruleActionsError([{ type: "addflag", value: "X" }])).toMatch(/not an action/);
    expect(ruleActionsError([{ type: "keep" }])).toMatch(/not an action/);
  });

  // The backend compares raw strings, so near-misses are not accepted there and
  // must not be shown as valid here.
  it("does not accept non-canonical spellings of a known type", () => {
    expect(ruleActionsError([{ type: "Keyword", value: "VIP" }])).toMatch(/not an action/);
    expect(ruleActionsError([{ type: " archive" }])).toMatch(/not an action/);
  });

  it("rejects two actions that both change visibility", () => {
    expect(ruleActionsError([{ type: "archive" }, { type: "read" }])).toMatch(/only do one of/);
  });

  it("rejects a visibility-changing action that is not last", () => {
    expect(ruleActionsError([{ type: "archive" }, { type: "keyword", value: "VIP" }])).toMatch(
      /last action/
    );
    expect(
      ruleActionsError([{ type: "move", value: "Later" }, { type: "stop" }, { type: "keyword", value: "VIP" }])
    ).toMatch(/last action/);
  });

  it("requires a value where the action carries one", () => {
    expect(ruleActionsError([{ type: "keyword", value: "" }])).toMatch(/needs a keyword/);
    expect(ruleActionsError([{ type: "keyword", value: "   " }])).toMatch(/needs a keyword/);
    expect(ruleActionsError([{ type: "move" }])).toMatch(/target folder/);
    expect(ruleActionsError([{ type: "read" }])).toBe("");
  });

  it("caps the action count", () => {
    const many = Array.from({ length: MAX_ACTIONS_PER_RULE + 1 }, () => ({
      type: "keyword",
      value: "K"
    }));
    expect(ruleActionsError(many)).toMatch(/at most/);
    expect(ruleActionsError(many.slice(0, MAX_ACTIONS_PER_RULE))).toBe("");
  });

  it("classifies which actions take a message out of the retry query", () => {
    for (const t of ["read", "move", "archive", "spam", "delete"]) {
      expect(isVisibilityChanging(t)).toBe(true);
    }
    for (const t of ["keyword", "unkeyword", "stop"]) {
      expect(isVisibilityChanging(t)).toBe(false);
    }
  });
});
