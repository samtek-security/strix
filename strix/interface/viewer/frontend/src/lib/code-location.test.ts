// Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
import assert from "node:assert/strict";
import { test } from "node:test";

import { formatCodeLocation, repoMatchesUrl } from "./code-location.ts";

test("a location naming its repository reads repo: file:line", () => {
  assert.equal(formatCodeLocation({ repo: "acme/api", file: "app/views.py", start_line: 3 }), "acme/api: app/views.py:3");
  assert.equal(
    formatCodeLocation({ repo: "acme/web", file: "app/views.py", start_line: 3, end_line: 9 }),
    "acme/web: app/views.py:3-9",
  );
});

test("two repositories with one path read differently", () => {
  const api = formatCodeLocation({ repo: "acme/api", file: "src/app.py", start_line: 10 });
  const web = formatCodeLocation({ repo: "acme/web", file: "src/app.py", start_line: 10 });
  assert.notEqual(api, web);
});

test("a location naming no repository is unchanged", () => {
  assert.equal(formatCodeLocation({ file: "app/views.py", start_line: 3 }), "app/views.py:3");
  assert.equal(formatCodeLocation({ file: "app/views.py", start_line: 3, end_line: 3 }), "app/views.py:3");
  assert.equal(formatCodeLocation({ file: "app/views.py", start_line: 3, end_line: 5 }), "app/views.py:3-5");
  assert.equal(formatCodeLocation({ repo: "", file: "a.py" }, false), "a.py");
});

test("a repository matches its URL by exact name, not by substring", () => {
  assert.equal(repoMatchesUrl("acme/api", "https://github.com/acme/api"), true);
  assert.equal(repoMatchesUrl("acme/api", "https://github.com/acme/api.git"), true);
  assert.equal(repoMatchesUrl("acme/api", "git@github.com:acme/api.git"), true);
  assert.equal(repoMatchesUrl("acme__api", "https://github.com/acme/api"), false);
  assert.equal(repoMatchesUrl("API", "https://github.com/acme/api"), true);
  assert.equal(repoMatchesUrl("api", "https://github.com/acme/web-api"), false);
  assert.equal(repoMatchesUrl("acme/api", "https://github.com/acme/api-gateway"), false);
  assert.equal(repoMatchesUrl("other/api", "https://github.com/acme/api"), false);
  assert.equal(repoMatchesUrl("", "https://github.com/acme/api"), false);
});
