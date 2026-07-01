"""
Help — one place that accounts for EVERYTHING Ghosted does.

HELP is the single source of truth for every command + capability. The console `help`
command and the homepage /help page both render from here, so there's never drift
between what the app does and what it says it does.
"""

from __future__ import annotations

# category -> list of (command, summary, detail)
HELP: dict[str, list[tuple[str, str, str]]] = {
    "Search & privacy": [
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
            "home [port]",
            "open the search website (GUI)",
            "Starts Ghosted's own Google-like search homepage (ghost logo + centered search bar + "
            "results layout, history/favorites/voice) on a local port (default 7654) and opens it in "
            "your browser. The server runs in a background thread so the console stays interactive; "
            "the page is Gojo-gated and fail-closed to localhost. Aliases: gui, web.",
        ),
        (
            "forge <path>",
            "produce a unique, equivalent artifact",
            "Generates a functionally-equivalent but byte-distinct version of a source file.",
        ),
        (
            "cloak <img> <msg>",
            "hide an encrypted message in an image (stego)",
            "Encrypts the message with GHOSTED-CIPHER-1, then LSB-embeds it in the image. A true "
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
            "seal text with GHOSTED-CIPHER-1",
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
            "Sets or verifies the master password (GHOSTED-KDF). Required before building a mesh; "
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
        (
            "flush",
            "flush spooled mesh-mail + fetch now",
            "Forces a store-and-forward pass: re-delivers spooled @sovereign.dmn mesh mail to "
            "peers and replays spooled URL fetches. A background flusher also runs this whenever "
            "connectivity returns, so it usually happens on its own.",
        ),
        (
            "mesh [export [dir]]",
            "mesh status, or export sealed configs",
            "'mesh' reports whether a sealed WireGuard mesh exists; 'mesh export [dir]' unlocks the "
            "vault with the master password and writes each device's importable .conf (Add Tunnel "
            "from file in WireGuard) — the actuation step for a mesh built with 'network'.",
        ),
        (
            "passwd",
            "rotate the master password",
            "Verifies the current password, sets a new one (min 12 chars), and re-seals the "
            "WireGuard mesh under the new key in one step. Only an encrypted verifier is stored.",
        ),
    ],
    "Mail": [
        (
            "mail [sub]",
            "black-box mail: inbox / read / compose / send / ext / pull",
            "One command for the whole mailbox. 'mail' or 'mail inbox' lists black boxes; "
            "'mail read <index|path>' opens one with your passphrase; 'mail compose' seals a "
            "message into your local mailbox; 'mail send <peer-host>' delivers a sealed @sovereign.dmn "
            "black box to a peer over the WireGuard mesh (spooled if the peer is offline); "
            "'mail ext' relays one message via external SMTP submission (leaves the sovereign "
            "envelope; credentials used for that call only, never stored); 'mail pull <imap|pop>' "
            "opt-in fetches an external inbox over verified TLS and black-boxes each message at rest.",
        ),
        (
            "identity [add|rm <email>]",
            "use your own email (no IMAP/POP by default)",
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
            "Parses pdf/docx/html/csv/json/txt; images go through OCR (rapidocr/pytesseract) when the engine "
            "is installed (pip install .[ocr]).",
        ),
    ],
    "Safety + diagnostics": [
        (
            "scan <path> [q]",
            "EDR-lite file safety check",
            "Dependency-free triage of a file: SHA-256, risky extension, executable/magic-byte "
            "sniff, extension/content mismatch, and entropy (packed/encrypted). Verdict is "
            "clean/suspicious/malicious; add 'q' to quarantine a malicious file (moved inert, "
            "renamed). Consults the rabbit mind's EDR too when present.",
        ),
        (
            "doctor",
            "report which capabilities are wired (+ optional deps)",
            "Checks every declared capability — each backed by one of Ghosted's own modules — "
            "and reports whether it is importable and whether its optional backing library is "
            "installed, so you can see exactly what works now and what `pip install` would unlock.",
        ),
        (
            "health",
            "device health monitor",
            "A sovereign, pure-Python read of the machine: CPU, memory, disk, battery, uptime, "
            "network connectivity, and security posture (EDR + egress IP), each with an ok/warn/"
            "critical state and one overall verdict. Also a live panel on the website at /health.",
        ),
    ],
    "Account + learning": [
        (
            "setup",
            "guided account setup (name·email·text·2FA·location)",
            "Captures everything at account setup: master password, display name, your email(s) "
            "(with 2nd/3rd fallbacks), a mobile number + carrier for text codes, an authenticator "
            "(QR + secret), a trusted-location factor, and one-time recovery codes. Multi-factor so "
            "two factors are required at login. Also available as onboarding on the website.",
        ),
        (
            "account",
            "your account info: personal data + history + stats",
            "Shows all your personal data (display name, identities, email accounts, enrolled MFA "
            "factors), your recent search history, and your usage statistics. On the website the "
            "signed-in name links to this same page.",
        ),
        (
            "mfa",
            "multi-factor status",
            "Two means of identification are required: the master password PLUS two enrolled factors "
            "from authenticator(QR/TOTP), email code, text message, trusted location, and recovery "
            "codes. Every one-time code is generated + sealed with sovereign encryption (one-time "
            "use), and verification is fail-soft (clock-drift window + recovery escape).",
        ),
        (
            "prefs [set <k> <v>]",
            "customize your experience",
            "Per-account preferences: accent theme, optional notifications (off by default) and which "
            "kinds, Lola voice auto-read, relevance badges, and display name. 'prefs' shows them; "
            "'prefs set <key> <value>' changes one; 'prefs reset' restores defaults.",
        ),
        (
            "notify",
            "your optional notifications",
            "Opt-in notices (health alerts, new mail, learning suggestions) — only shown when you "
            "enable them in prefs, and only to you (the signed-in account holder).",
        ),
        (
            "feedback [sub]",
            "the learning loop — every input is a data point",
            "Ghosted learns from how searches are used: result clicks, dwell time, and 👍/👎 ratings "
            "float helpful results up next time, scaled by how much data the loop has earned "
            "(adaptivity). 'feedback' shows the rollup; 'feedback good|bad <query>' rates a query; "
            "'feedback rate <score> <query>' gives an explicit 1–5 / -1..1 score. The website "
            "captures clicks and dwell automatically via beacons.",
        ),
    ],
    "Open use": [
        (
            "open access",
            "full capabilities for everyone; personal data stays private",
            "The website (public domain http://sovereign.dmn:7654) serves every capability — search, "
            "spell-corrected results, device health, help — to any guest on any connection, no account "
            "needed. Personal data (your vault, mail, identities, and mesh) is the ONLY thing behind the "
            "account gate; sign in at /account (or create an account there on first run).",
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
    "Ghosted also runs a sovereign Google-like homepage (search + spell-corrected results + "
    "meaning-ranking + tabs + private on-device history/favorites + a Lola read-aloud button + a "
    "live device-health panel) at the public domain http://sovereign.dmn:7654 — OPEN USE: every "
    "capability is available to any guest on any connection, while personal data (vault, mail, "
    "identities, mesh) stays behind the account gate. It learns from use — clicks, dwell, and "
    "ratings adapt ranking (every input is a data point). Plus a black-box mail system "
    "(@sovereign.dmn end-to-end + real mesh delivery + opt-in IMAP/POP receive + external SMTP "
    "send) and a WireGuard key vault — all sovereign, hardened, and degrading gracefully when an "
    "optional engine isn't present."
)


def overview() -> str:
    lines = ["Ghosted — everything it does:\n"]
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
