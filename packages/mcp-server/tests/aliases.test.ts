import { describe, it, expect } from "vitest";

import {
  ALL_TOOL_NAMES,
  LEGACY_TO_V2_ALIASES,
  V2_TO_LEGACY_ALIASES,
  expandWithAliases,
  normalizeToolName,
} from "../src/aliases";

describe("LEGACY_TO_V2_ALIASES", () => {
  it("covers all nine MCP tools", () => {
    const expected = [
      "spize_whoami",
      "spize_init",
      "spize_send",
      "spize_inbox",
      "spize_download",
      "spize_ack",
      "spize_send_via_tunnel",
      "spize_request_ticket",
      "spize_fetch_from_tunnel",
    ];
    for (const k of expected) {
      expect(LEGACY_TO_V2_ALIASES[k]).toBeDefined();
      expect(LEGACY_TO_V2_ALIASES[k]).toBe(k.replace("spize_", "aex_"));
    }
  });

  it("is bijective with V2_TO_LEGACY_ALIASES", () => {
    for (const [legacy, v2] of Object.entries(LEGACY_TO_V2_ALIASES)) {
      expect(V2_TO_LEGACY_ALIASES[v2]).toBe(legacy);
    }
  });

  it("ALL_TOOL_NAMES contains every legacy + v2 entry", () => {
    for (const k of Object.keys(LEGACY_TO_V2_ALIASES)) {
      expect(ALL_TOOL_NAMES).toContain(k);
    }
    for (const k of Object.keys(V2_TO_LEGACY_ALIASES)) {
      expect(ALL_TOOL_NAMES).toContain(k);
    }
  });

  it("freezes the maps so callers can't mutate them at runtime", () => {
    expect(Object.isFrozen(LEGACY_TO_V2_ALIASES)).toBe(true);
    expect(Object.isFrozen(V2_TO_LEGACY_ALIASES)).toBe(true);
  });
});

describe("normalizeToolName", () => {
  function freshState() {
    return { warned: new Set<string>() };
  }

  it("returns v2 name unchanged", () => {
    const out = normalizeToolName("aex_send", freshState(), () => {});
    expect(out).toBe("aex_send");
  });

  it("maps legacy → v2 and emits warning once", () => {
    const warnings: string[] = [];
    const state = freshState();
    const out1 = normalizeToolName("spize_send", state, (m) => warnings.push(m));
    const out2 = normalizeToolName("spize_send", state, (m) => warnings.push(m));
    expect(out1).toBe("aex_send");
    expect(out2).toBe("aex_send");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("spize_send");
    expect(warnings[0]).toContain("aex_send");
    expect(warnings[0]).toContain("deprecated");
  });

  it("warns once per distinct legacy name", () => {
    const warnings: string[] = [];
    const state = freshState();
    normalizeToolName("spize_send", state, (m) => warnings.push(m));
    normalizeToolName("spize_inbox", state, (m) => warnings.push(m));
    normalizeToolName("spize_send", state, (m) => warnings.push(m));
    expect(warnings).toHaveLength(2);
  });

  it("returns unknown names unchanged without warning", () => {
    const warnings: string[] = [];
    const out = normalizeToolName("unrelated_tool", freshState(), (m) =>
      warnings.push(m),
    );
    expect(out).toBe("unrelated_tool");
    expect(warnings).toHaveLength(0);
  });
});

describe("expandWithAliases", () => {
  const SAMPLE_DEFS = [
    {
      name: "aex_whoami",
      description: "Return identity.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "aex_send",
      description: "Send a file.",
      inputSchema: { type: "object", properties: {} },
    },
  ];

  it("produces both v2 and legacy entries", () => {
    const out = expandWithAliases(SAMPLE_DEFS);
    const names = out.map((d) => d.name);
    expect(names).toContain("aex_whoami");
    expect(names).toContain("spize_whoami");
    expect(names).toContain("aex_send");
    expect(names).toContain("spize_send");
  });

  it("marks legacy entries DEPRECATED", () => {
    const out = expandWithAliases(SAMPLE_DEFS);
    const legacy = out.find((d) => d.name === "spize_send");
    expect(legacy?.description).toContain("DEPRECATED");
    expect(legacy?.description).toContain("aex_send");
  });

  it("preserves the v2 schema on the legacy entry", () => {
    const out = expandWithAliases(SAMPLE_DEFS);
    const v2 = out.find((d) => d.name === "aex_send");
    const legacy = out.find((d) => d.name === "spize_send");
    expect(legacy?.inputSchema).toBe(v2?.inputSchema);
  });
});
