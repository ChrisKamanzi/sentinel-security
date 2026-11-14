import { afterEach, describe, expect, it, vi } from "vitest";

// client.ts reads VITE_API_BASE_URL at import time, so each case re-imports it.
async function loadClient(env: { base?: string; ssr?: boolean; proc?: Record<string, string> }) {
  vi.resetModules();
  vi.stubEnv("VITE_API_BASE_URL", env.base ?? "");
  vi.stubEnv("SSR", env.ssr ?? false);
  for (const key of ["API_INTERNAL_URL", "API_PROXY_TARGET"]) delete process.env[key];
  Object.assign(process.env, env.proc ?? {});
  return import("@/lib/api/client");
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  delete process.env["API_INTERNAL_URL"];
  delete process.env["API_PROXY_TARGET"];
});

describe("API client URLs", () => {
  it("is in demo mode when VITE_API_BASE_URL is unset", async () => {
    const c = await loadClient({});
    expect(c.isDemoMode).toBe(true);
  });

  it("uses /api/v1 exactly once in the browser (Vite proxy path)", async () => {
    const c = await loadClient({ base: "/api/v1" });
    expect(c.isDemoMode).toBe(false);
    expect(c.apiUrl("/dashboard/summary")).toBe("/api/v1/dashboard/summary");
  });

  it("ignores a trailing slash on the base", async () => {
    const c = await loadClient({ base: "/api/v1/" });
    expect(c.apiUrl("/findings")).toBe("/api/v1/findings");
  });

  it("calls FastAPI on 127.0.0.1:8001 during SSR by default", async () => {
    const c = await loadClient({ base: "/api/v1", ssr: true });
    expect(c.internalApiOrigin()).toBe("http://127.0.0.1:8001");
    expect(c.apiUrl("/assessments")).toBe("http://127.0.0.1:8001/api/v1/assessments");
  });

  it("lets API_INTERNAL_URL override the SSR origin", async () => {
    const c = await loadClient({
      base: "/api/v1",
      ssr: true,
      proc: { API_INTERNAL_URL: "http://backend:9000/", API_PROXY_TARGET: "http://ignored:1" },
    });
    expect(c.apiUrl("/reports")).toBe("http://backend:9000/api/v1/reports");
  });

  it("falls back to API_PROXY_TARGET for SSR when API_INTERNAL_URL is unset", async () => {
    const c = await loadClient({
      base: "/api/v1",
      ssr: true,
      proc: { API_PROXY_TARGET: "http://127.0.0.1:9100" },
    });
    expect(c.apiUrl("/reports")).toBe("http://127.0.0.1:9100/api/v1/reports");
  });

  it("uses an absolute base as-is in both browser and SSR", async () => {
    const browser = await loadClient({ base: "https://api.example.com/api/v1" });
    expect(browser.apiUrl("/findings")).toBe("https://api.example.com/api/v1/findings");
    const ssr = await loadClient({ base: "https://api.example.com/api/v1", ssr: true });
    expect(ssr.apiUrl("/findings")).toBe("https://api.example.com/api/v1/findings");
  });
});

describe("service layer paths", () => {
  it("never doubles the /api prefix", async () => {
    vi.resetModules();
    vi.stubEnv("VITE_API_BASE_URL", "/api/v1");
    vi.stubEnv("SSR", false);
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { api } = await import("@/lib/api/services");

    await api.getDashboard();
    await api.listAssessments();
    await api.getScan("s1");
    await api.listFindings();
    await api.getFinding("f1");
    await api.listReports();
    await api.createAssessment({
      target: "https://x.test",
      name: "x",
      authorized: true,
      profile: "quick",
      modules: [],
      maxRps: 5,
    });
    await api.askAnalyst([{ role: "user", content: "hi" }]);

    const urls = fetchMock.mock.calls.map((call) => String((call as unknown[])[0]));
    expect(urls).toEqual([
      "/api/v1/dashboard/summary",
      "/api/v1/assessments",
      "/api/v1/assessments/s1",
      "/api/v1/findings",
      "/api/v1/findings/f1",
      "/api/v1/reports",
      "/api/v1/assessments",
      "/api/v1/analyst/chat",
    ]);
    expect(api.reportDownloadUrl("r1")).toBe("/api/v1/reports/r1/download");
  });
});
