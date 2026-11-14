import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { StatusBadge, Unavailable } from "@/components/app/ui";
import { fmtCvss, fmtSize } from "@/lib/format";
import type { ScanStatus } from "@/lib/api/types";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("value formatting for missing backend data", () => {
  it("formats CVSS and reports null as unavailable", () => {
    expect(fmtCvss(7.5)).toBe("7.5");
    expect(fmtCvss(0)).toBe("0.0"); // a real 0.0 score is still a score
    expect(fmtCvss(null)).toBeNull();
  });

  it("formats report sizes in KB below 1 MB", () => {
    expect(fmtSize(18.1)).toBe("18.1 KB");
    expect(fmtSize(2480)).toBe("2.4 MB");
  });

  it("renders an explained placeholder", () => {
    render(<Unavailable label="Not tracked" reason="The backend does not count requests" />);
    expect(screen.getByText("Not tracked")).toHaveAttribute(
      "title",
      "The backend does not count requests",
    );
  });
});

describe("StatusBadge", () => {
  it.each<[ScanStatus, string]>([
    ["queued", "text-muted-foreground"],
    ["running", "text-primary"],
    ["completed", "text-success"],
    ["partial", "text-sev-medium"],
    ["failed", "text-destructive"],
  ])("styles %s distinctly", (status, cls) => {
    render(<StatusBadge status={status} />);
    expect(screen.getByText(status)).toHaveClass(cls);
  });

  it("never styles partial as completed", () => {
    render(<StatusBadge status="partial" />);
    const badge = screen.getByText("partial");
    expect(badge).not.toHaveClass("text-success");
    expect(badge).toHaveAttribute("title", "Some scanners completed, others failed");
  });

  it("falls back to a neutral style for an unknown status", () => {
    render(<StatusBadge status={"cancelled" as ScanStatus} />);
    expect(screen.getByText("cancelled")).toHaveClass("text-muted-foreground");
  });
});

describe("getFinding", () => {
  async function loadServices(fetchImpl: () => Promise<Response>) {
    vi.resetModules();
    vi.stubEnv("VITE_API_BASE_URL", "/api/v1");
    vi.stubEnv("SSR", false);
    const fetchMock = vi.fn(fetchImpl);
    vi.stubGlobal("fetch", fetchMock);
    const { api } = await import("@/lib/api/services");
    return { api, fetchMock };
  }

  it("uses the UI detail endpoint", async () => {
    const { api, fetchMock } = await loadServices(
      async () => new Response('{"id":"f1"}', { status: 200 }),
    );
    await expect(api.getFinding("f1")).resolves.toEqual({ id: "f1" });
    expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toBe("/api/v1/findings/f1/detail");
  });

  it.each([404, 422])("treats HTTP %i as not found", async (status) => {
    const { api } = await loadServices(async () => new Response('{"detail":"nope"}', { status }));
    await expect(api.getFinding("missing")).resolves.toBeNull();
  });

  it("surfaces other errors", async () => {
    const { api } = await loadServices(
      async () => new Response('{"detail":"boom"}', { status: 500 }),
    );
    await expect(api.getFinding("f1")).rejects.toThrow("boom");
  });
});
