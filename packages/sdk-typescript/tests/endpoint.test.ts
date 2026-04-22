import { describe, it, expect } from "vitest";

import {
  KIND_CLOUDFLARE_QUICK,
  KIND_FRP,
  KIND_IROH,
  endpointFromJson,
  endpointToJson,
  isHttpDialable,
  isKnownKind,
  sortByPriority,
  succeeded,
  tryEndpoints,
  type Endpoint,
} from "../src/endpoint.js";

describe("endpoint", () => {
  it("round-trips without health hint", () => {
    const ep: Endpoint = {
      kind: KIND_CLOUDFLARE_QUICK,
      url: "https://x.trycloudflare.com",
      priority: 0,
    };
    const j = endpointToJson(ep);
    expect(j).toEqual({
      kind: "cloudflare_quick",
      url: "https://x.trycloudflare.com",
      priority: 0,
    });
    expect(endpointFromJson(j)).toEqual(ep);
  });

  it("round-trips with health hint", () => {
    const ep: Endpoint = {
      kind: KIND_IROH,
      url: "iroh:abc@relay.aex.dev:443",
      priority: 1,
      healthHintUnix: 1_700_000_000,
    };
    const j = endpointToJson(ep);
    expect(j.health_hint_unix).toBe(1_700_000_000);
    expect(endpointFromJson(j)).toEqual(ep);
  });

  it("classifies known vs unknown kinds", () => {
    expect(isKnownKind({ kind: KIND_FRP, url: "", priority: 0 })).toBe(true);
    expect(
      isKnownKind({ kind: "future_transport_v9", url: "", priority: 0 }),
    ).toBe(false);
  });

  it("marks iroh as known-but-not-HTTP-dialable", () => {
    const ep: Endpoint = { kind: KIND_IROH, url: "iroh:abc", priority: 0 };
    expect(isKnownKind(ep)).toBe(true);
    expect(isHttpDialable(ep)).toBe(false);
  });

  it("sorts stably by priority", () => {
    const eps: Endpoint[] = [
      { kind: KIND_FRP, url: "a", priority: 5 },
      { kind: KIND_FRP, url: "b", priority: 1 },
      { kind: KIND_FRP, url: "c", priority: 1 },
    ];
    const out = sortByPriority(eps);
    expect(out.map((e) => e.url)).toEqual(["b", "c", "a"]);
    // Input not mutated.
    expect(eps.map((e) => e.url)).toEqual(["a", "b", "c"]);
  });
});

describe("tryEndpoints", () => {
  it("picks the first success and stops", async () => {
    const hit: string[] = [];
    const eps: Endpoint[] = [
      { kind: KIND_FRP, url: "first", priority: 0 },
      { kind: KIND_FRP, url: "second", priority: 1 },
    ];
    const result = await tryEndpoints(eps, async (ep) => {
      hit.push(ep.url);
      return `fetched:${ep.url}`;
    });
    expect(succeeded(result)).toBe(true);
    expect(result.value).toBe("fetched:first");
    expect(result.chosen?.url).toBe("first");
    expect(hit).toEqual(["first"]);
  });

  it("falls through on per-endpoint error", async () => {
    const eps: Endpoint[] = [
      { kind: KIND_FRP, url: "broken", priority: 0 },
      { kind: KIND_FRP, url: "working", priority: 1 },
    ];
    const result = await tryEndpoints(eps, async (ep) => {
      if (ep.url === "broken") throw new Error("kaboom");
      return "ok";
    });
    expect(succeeded(result)).toBe(true);
    expect(result.chosen?.url).toBe("working");
    expect(result.attempts).toHaveLength(2);
    expect(result.attempts[0].error).toBe("kaboom");
    expect(result.attempts[1].ok).toBe(true);
  });

  it("skips iroh and unknown kinds", async () => {
    const skipped: Array<[string, string]> = [];
    const eps: Endpoint[] = [
      { kind: KIND_IROH, url: "iroh:a", priority: 0 },
      { kind: "future_transport_v9", url: "alien:x", priority: 1 },
      { kind: KIND_FRP, url: "https://frp.ok", priority: 2 },
    ];
    const result = await tryEndpoints(
      eps,
      async () => "ok",
      {
        onSkip: (ep, reason) => skipped.push([ep.kind, reason]),
      },
    );
    expect(succeeded(result)).toBe(true);
    expect(result.chosen?.url).toBe("https://frp.ok");
    expect(skipped.some(([k]) => k === "iroh")).toBe(true);
    expect(skipped.some(([k]) => k === "future_transport_v9")).toBe(true);
  });

  it("returns unsucceeded when every attempt fails", async () => {
    const eps: Endpoint[] = [
      { kind: KIND_FRP, url: "a", priority: 0 },
      { kind: KIND_FRP, url: "b", priority: 1 },
    ];
    const result = await tryEndpoints(eps, async (ep) => {
      throw new Error(`fail ${ep.url}`);
    });
    expect(succeeded(result)).toBe(false);
    expect(result.chosen).toBeUndefined();
    expect(result.attempts).toHaveLength(2);
    expect(result.attempts.every((a) => a.error !== undefined)).toBe(true);
  });

  it("handles empty endpoint list", async () => {
    const result = await tryEndpoints<string>([], async () => "ok");
    expect(succeeded(result)).toBe(false);
    expect(result.attempts).toEqual([]);
  });

  it("respects sender priority across insertion order", async () => {
    const hit: string[] = [];
    const eps: Endpoint[] = [
      { kind: KIND_FRP, url: "low", priority: 5 },
      { kind: KIND_FRP, url: "high", priority: 0 },
    ];
    await tryEndpoints(eps, async (ep) => {
      hit.push(ep.url);
      return "ok";
    });
    expect(hit).toEqual(["high"]);
  });
});
