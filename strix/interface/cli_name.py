# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""The command name users type, shared by the help text and shell completions.

Upstream calls the console script ``strix``; this fork installs ``recon``
(``[project.scripts]`` in pyproject.toml). Keeping the name here means an
upstream sync conflicts in one place instead of reintroducing ``strix`` in
one snippet.
"""

CLI_NAME = "recon"
