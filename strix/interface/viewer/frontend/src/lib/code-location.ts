// Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
// A code location's reference text. Two repositories can hold the same path, so a location that names
// its repository reads `repo: file:line`; one that names none reads `file:line`, as before.
export interface LocationRef {
  repo?: string;
  file: string;
  start_line?: number;
  end_line?: number;
}

export function formatCodeLocation(loc: LocationRef, withLines = true): string {
  const where = loc.repo ? `${loc.repo}: ${loc.file}` : loc.file;
  if (!withLines || !loc.start_line) return where;
  return loc.end_line && loc.end_line !== loc.start_line
    ? `${where}:${loc.start_line}-${loc.end_line}`
    : `${where}:${loc.start_line}`;
}

// True when `repo` names the repository `repoUrl` points at. Matches owner/name or a bare name against the URL's path segments exactly, so `api` never matches `acme/web-api`.
export function repoMatchesUrl(repo: string, repoUrl: string): boolean {
  const want = repo.trim().toLowerCase().replace(/\.git$/, "");
  if (!want) return false;
  const path = repoUrl.trim().toLowerCase().replace(/^[a-z+]+:\/\/[^/]+\//, "").replace(/^[^@/]+@[^:]+:/, "");
  const parts = path.replace(/\.git$/, "").split("/").filter(Boolean);
  const have = want.includes("/") ? parts.slice(-want.split("/").length).join("/") : parts[parts.length - 1];
  return have === want;
}
