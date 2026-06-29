"""Help feature — covers everything; no drift between commands and their docs."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ghosted import help_text  # noqa: E402


def test_overview_and_detail():
    ov = help_text.overview()
    for token in ("recon", "mailsearch", "connect", "hotspot", "cloak", "identity"):
        assert token in ov
    assert "black box" in help_text.detail("cloak").lower()
    assert "no help" in help_text.detail("bogus")


def test_help_documents_every_console_command():
    helped = {c.split()[0] for items in help_text.HELP.values() for (c, _, _) in items}
    for cmd in (
        "recon",
        "browse",
        "forge",
        "cloak",
        "uncloak",
        "encrypt",
        "decrypt",
        "login",
        "network",
        "connect",
        "hotspot",
        "spool",
        "identity",
        "contacts",
        "filters",
        "mailsearch",
        "parse",
        "status",
        "help",
        "quit",
    ):
        assert cmd in helped, f"'{cmd}' missing from HELP — docs drifted from commands"


def test_homepage_help_page_renders():
    from ghosted import homepage as h

    page = h._help_page()
    assert "Ghosted" in page and "recon" in page and "stego" in page.lower()
