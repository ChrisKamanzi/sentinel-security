/** One-decimal CVSS, or null when the scanner reported no score. */
export function fmtCvss(cvss: number | null): string | null {
  return cvss == null ? null : cvss.toFixed(1);
}

export function fmtSize(sizeKb: number): string {
  return sizeKb >= 1024 ? `${(sizeKb / 1024).toFixed(1)} MB` : `${sizeKb.toFixed(1)} KB`;
}
