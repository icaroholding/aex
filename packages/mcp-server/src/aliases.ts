/**
 * Tool-name aliasing for the v1 → v2 brand transition.
 *
 * Wire-format v2 (ADR-0042) drops the `spize-` prefix from canonical
 * bytes; the MCP tool names follow suit. Every `spize_*` tool gets an
 * `aex_*` alias that ships at v2.0; the `spize_*` names remain
 * callable for at least one year after GA to give Claude Desktop /
 * Cursor / Cline / custom MCP hosts time to migrate their saved tool
 * invocations.
 *
 * On every `spize_*` call we emit a one-line deprecation note to
 * `stderr`. We do NOT log it on every call — that would be spammy in
 * long-running sessions — only the first time per process per tool.
 *
 * # Why a separate module
 *
 * `index.ts` is large and side-effectful (starts the MCP server on
 * import). This file is pure data + pure functions so the test in
 * `tests/aliases.test.ts` exercises the alias mapping without dragging
 * in the SDK, identity loading, or the MCP runtime.
 */

/**
 * Canonical (v2) tool name for each historical (v1) name.
 *
 * Order matches the order of declarations in `TOOL_DEFS` (`index.ts`).
 * Every legacy name MUST have a v2 alias; the test
 * `every_legacy_tool_has_v2_alias` asserts this against the runtime
 * tool list.
 */
export const LEGACY_TO_V2_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  spize_whoami: "aex_whoami",
  spize_init: "aex_init",
  spize_send: "aex_send",
  spize_inbox: "aex_inbox",
  spize_download: "aex_download",
  spize_ack: "aex_ack",
  spize_send_via_tunnel: "aex_send_via_tunnel",
  spize_request_ticket: "aex_request_ticket",
  spize_fetch_from_tunnel: "aex_fetch_from_tunnel",
});

/** Reverse map. Useful when generating tool definitions. */
export const V2_TO_LEGACY_ALIASES: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(
    Object.entries(LEGACY_TO_V2_ALIASES).map(([legacy, v2]) => [v2, legacy]),
  ),
);

/** All known (v1 + v2) tool names. */
export const ALL_TOOL_NAMES: readonly string[] = [
  ...Object.keys(LEGACY_TO_V2_ALIASES),
  ...Object.keys(V2_TO_LEGACY_ALIASES),
];

/** Side effect emitter for deprecation notices. Replaced in tests. */
export type DeprecationEmitter = (msg: string) => void;

const DEFAULT_EMITTER: DeprecationEmitter = (msg) => {
  process.stderr.write(msg + "\n");
};

/**
 * Resolve a (possibly legacy) tool name to its canonical (v2) form.
 *
 * Returns `name` unchanged if it's already v2 or unknown. Emits a
 * one-shot per-tool deprecation warning the first time a legacy name
 * is seen in a given process.
 */
export function normalizeToolName(
  name: string,
  state: { warned: Set<string> } = SHARED_WARN_STATE,
  emit: DeprecationEmitter = DEFAULT_EMITTER,
): string {
  const v2 = LEGACY_TO_V2_ALIASES[name];
  if (!v2) return name;
  if (!state.warned.has(name)) {
    state.warned.add(name);
    emit(
      `aex-mcp: tool '${name}' is deprecated; use '${v2}' instead. ` +
        `Legacy names remain callable through the v1→v2 grace window (ADR-0043).`,
    );
  }
  return v2;
}

/**
 * Process-global warn-tracker. Lives in the module scope so multiple
 * `dispatch` calls inside the same MCP session share one set.
 */
const SHARED_WARN_STATE = { warned: new Set<string>() };

/**
 * Build the full list of tool definitions: each entry in `defs` is
 * the v2 canonical version, and the helper produces both the v2 and
 * the legacy alias side by side. Used by `index.ts` to expose both
 * names through the MCP `tools/list` response.
 *
 * The two versions share the same `inputSchema`; the descriptions
 * differ to clarify which is canonical.
 */
export function expandWithAliases<
  T extends { name: string; description: string; inputSchema: unknown },
>(defs: readonly T[]): T[] {
  const out: T[] = [];
  for (const def of defs) {
    out.push(def);
    const legacy = V2_TO_LEGACY_ALIASES[def.name];
    if (legacy !== undefined) {
      out.push({
        ...def,
        name: legacy,
        description: `${def.description} [DEPRECATED — use '${def.name}'. Legacy alias retained per ADR-0043 grace window.]`,
      });
    }
  }
  return out;
}
