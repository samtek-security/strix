<!-- Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE. -->
# recon-browser

Browser automation CLI installed in the sandbox image. Driven by the agent
through `exec_command` (not a function tool).

- **Implementation:** sandbox CLI at
  `/home/pentester/.npm-global/bin/recon-browser` — npm package
  `recon-browser@0.26.0` (Vercel), driving Chromium directly.
- **Strix config:** `containers/Dockerfile` sets `AGENT_BROWSER_*` env
  (executable path, UA, launch args, screenshot dir).
- **Skill:** `strix/skills/tooling/agent_browser.md` — **always-loaded**
  into every agent prompt by `strix/agents/prompt.py:_resolve_skills`.
