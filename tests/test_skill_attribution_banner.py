# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
from pathlib import Path

import strix.skills as skills_mod
from strix.agents.prompt import render_system_prompt
from strix.skills import (
    _ATTRIBUTION_BANNER,
    _parse_skill_content,
    load_skills,
    register_skill_dir,
    skill_search_dirs,
)


FRONTMATTER = "---\nname: demo\ndescription: demo skill\n---\n"


def _load(tmp_path: Path, body: str) -> str:
    skills_mod._EXTRA_SKILL_DIRS.clear()
    (tmp_path / "tooling").mkdir()
    (tmp_path / "tooling" / "demo.md").write_text(FRONTMATTER + body, encoding="utf-8")
    register_skill_dir(tmp_path)
    try:
        return load_skills(["tooling/demo"])["demo"]
    finally:
        skills_mod._EXTRA_SKILL_DIRS.clear()


def test_leading_banner_line_is_removed(tmp_path: Path) -> None:
    out = _load(tmp_path, f"{_ATTRIBUTION_BANNER}\n\n# Demo\nbody\n")
    assert out == "# Demo\nbody\n"


def test_banner_after_blank_lines_is_removed() -> None:
    _, body = _parse_skill_content(FRONTMATTER + f"\n\n{_ATTRIBUTION_BANNER}\n# Demo\n")
    assert body == "# Demo\n"


def test_other_html_comments_are_preserved_byte_for_byte(tmp_path: Path) -> None:
    rest = "# Demo\n\n```html\n<!-- <script>alert(1)</script> -->\n<!--[if IE]>x<![endif]-->\n```\n"
    out = _load(tmp_path, f"{_ATTRIBUTION_BANNER}\n{rest}")
    assert out == rest


def test_other_leading_comment_is_preserved(tmp_path: Path) -> None:
    body = "<!-- reviewer note -->\n# Demo\n"
    assert _load(tmp_path, body) == body


def test_banner_that_is_not_the_whole_line_is_kept(tmp_path: Path) -> None:
    body = f"{_ATTRIBUTION_BANNER} trailing\n# Demo\n"
    assert _load(tmp_path, body) == body


def test_banner_later_in_body_is_kept(tmp_path: Path) -> None:
    body = f"# Demo\n{_ATTRIBUTION_BANNER}\n"
    assert _load(tmp_path, body) == body


def test_banner_without_frontmatter_is_removed() -> None:
    _, body = _parse_skill_content(f"{_ATTRIBUTION_BANNER}\n# Demo\n")
    assert body == "# Demo\n"


def test_source_files_keep_the_banner() -> None:
    builtin = skill_search_dirs()[-1]
    files = sorted(builtin.rglob("*.md"))
    bannered = [f for f in files if _ATTRIBUTION_BANNER in f.read_text(encoding="utf-8")]
    assert len(bannered) >= 40


def test_rendered_root_prompt_has_no_banner() -> None:
    for supports_images in (True, False):
        prompt = render_system_prompt(include_scope=False, supports_images=supports_images)
        assert "Modified by Samtek" not in prompt
        assert "Derived from Apache-2.0 Strix" not in prompt
        assert "See NOTICE" not in prompt
        assert "<!--" not in prompt
