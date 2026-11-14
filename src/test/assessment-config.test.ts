import { describe, expect, it } from "vitest";
import { profileScanners, validTargetUrl } from "@/lib/api/assessment-config";

describe("supported existing scanner profiles", () => {
  it("uses Nmap and Nuclei for quick", () => expect(profileScanners.quick).toEqual(["nmap", "nuclei"]));
  it("adds FFUF for standard", () => expect(profileScanners.standard).toEqual(["nmap", "ffuf", "nuclei"]));
  it("adds passive ZAP for deep", () => expect(profileScanners.deep).toEqual(["nmap", "ffuf", "nuclei", "zap"]));
  it("accepts an authorized HTTP or HTTPS URL", () => { expect(validTargetUrl("https://app.example.com:8443/path")).toBe(true); expect(validTargetUrl("http://127.0.0.1:8080")).toBe(true); });
  it("rejects embedded credentials", () => expect(validTargetUrl("https://user:secret@example.com")).toBe(false));
  it("rejects non-HTTP schemes and invalid ports", () => { expect(validTargetUrl("file:///etc/passwd")).toBe(false); expect(validTargetUrl("https://example.com:99999")).toBe(false); });
});