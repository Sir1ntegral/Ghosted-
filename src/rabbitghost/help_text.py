"""
Help — one place that accounts for EVERYTHING RabbitGhost does.

HELP is the single source of truth for every command + capability. The console `help`
command and the homepage /help page both render from here, so there's never drift
between what the app does and what it says it does.
"""

from __future__ import annotations

# category -> list of (command, summary, detail)
HELP: dict[str, list[tuple[str, str, str]]] = {
    "Ghost (stealth)": [
        (
            "recon <topic>",
            "stealth-investigate a topic",
            "Uses the SovereignBrowserEngine through ghost's masked, Tor-by-default path to "
            "gather + verify findings on a topic without revealing who's asking.",
        ),
        (
            "browse <query>",
            "sovereign web search",
            "Searches the web via the 5-engine TLS masks (chrome/firefox/edge/safari/tor145) "
            "with clearnet fallback, then re-ranks results by meaning, context, sentiment, and intent.",
        ),
        (
            "forge <path>",
            "produce a unique, equivalent artifact",
            "Generates a functionally-equivalent but byte-distinct version of a source file.",
        ),
        (
            "cloak <img> <msg>",
            "hide an encrypted message in an image (stego)",
            "Encrypts the message with RABBIT-CIPHER-1, then LSB-embeds it in the image. A true "
            "black box: the secret is absent from the output bytes; only the passphrase recovers it.",
        ),
        (
            "uncloak <img>",
            "extract a hidden message from an image",
            "Recovers + decrypts a cloaked payload with the passphrase. Wrong key reveals nothing.",
        ),
    ],
    "Crypto + vault": [
        (
            "encrypt <text>",
            "seal text with RABBIT-CIPHER-1",
            "Returns an opaque token only the passphrase opens.",
        ),
        (
            "decrypt",
            "open a sealed blob",
            "Paste the token + passphrase to recover the plaintext.",
        ),
        (
            "login",
            "unlock / set the master password",
            "Sets or verifies the master password (RABBIT-KDF). Required before building a mesh; "
            "stores only an encrypted verifier, never the password.",
        ),
    ],
    "Network + connectivity": [
        (
            "network",
            "build a sovereign WireGuard mesh (sealed)",
            "Generates a WireGuard PackMesh among your devices and seals every config in the vault. "
            "Requires login.",
        ),
        (
            "connect",
            "check internet across wifi/LAN/WAN",
            "Probes every interface; reports whether any path to the internet exists.",
        ),
        (
            "hotspot",
            "start a WiFi hotspot for the mesh",
            "Windows: stands up a hotspot (netsh) so peers join and the mesh runs over it. Needs admin.",
        ),
        (
            "spool",
            "store-and-forward outbox status",
            "Shows pending queued operations + online status. Queued ops auto-flush when a link returns.",
        ),
    ],
    "Mail": [
        (
            "identity [add|rm <email>]",
            "use your own email (no IMAP/POP)",
            "Register your own address of any provider as an identity only — never logs into an inbox. "
            "@sovereign.dmn is always suggested first.",
        ),
        (
            "contacts",
            "list saved contacts",
            "Names <-> addresses (sovereign or external).",
        ),
        (
            "filters",
            "list mail filter rules",
            "Rules that tag/star/block/route mail by from/to/subject/body.",
        ),
        (
            "mailsearch <q>",
            "search your black-box mail",
            "Opens each encrypted message with your passphrase and matches — black boxes aren't "
            "searchable without the key.",
        ),
    ],
    "Intake": [
        (
            "parse <path|text>",
            "extract text/structure",
            "Parses pdf/docx/html/csv/json/txt; images go through RABBIT-OCR-1 when the OCR engine "
            "is installed (pip install .[ocr]).",
        ),
    ],
    "Session": [
        ("status", "show ghost posture", "Whether ghost mode is active."),
        (
            "help [command]",
            "this help",
            "No argument: the full categorized overview. With a command: its detailed help.",
        ),
        ("quit", "stand down", "Drops all ghost components for GC and exits."),
    ],
}

CAPABILITIES = (
    "RabbitGhost also runs a sovereign Google-like homepage (search + meaning-ranking + tabs + "
    "private on-device history/favorites + a Lola read-aloud button + a Gojo-gated login for remote "
    "access over the mesh), a black-box mail system (@sovereign.dmn end-to-end + real mesh delivery + "
    "opt-in IMAP/POP receive + external SMTP send), and a WireGuard key vault — all sovereign, hardened, "
    "and degrading gracefully when an optional engine isn't present."
)


def overview() -> str:
    lines = ["RabbitGhost — everything it does:\n"]
    for cat, items in HELP.items():
        lines.append(f"  {cat}")
        for cmd, summary, _detail in items:
            lines.append(f"    {cmd:<26} {summary}")
        lines.append("")
    lines.append(CAPABILITIES)
    lines.append("\n(type  help <command>  for detail)")
    return "\n".join(lines)


def detail(command: str) -> str:
    key = (command or "").strip().lower().split()[0] if command else ""
    for items in HELP.values():
        for cmd, summary, det in items:
            if cmd.split()[0].lower() == key:
                return f"{cmd}\n  {summary}\n\n  {det}"
    return f"no help for '{command}'. Type 'help' for the full list."
