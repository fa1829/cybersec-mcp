"""Password analysis against NIST SP 800-63B.

v1 of this tool reported `P@ssw0rd123` as 72.1 bits of entropy with the note
"entropy is sufficient for strong protection", while simultaneously flagging it
as a common password. Both statements came from the same function, and the
entropy one was wrong.

The bug is the formula, not the arithmetic: `log2(charset) x length` measures
the size of the space a password *could* have been drawn from, which only bounds
strength if the password was generated uniformly at random from that space.
Human-chosen passwords are not, so the number is an upper bound and nothing more.
This version says so, and leads with guessability instead.
"""

from __future__ import annotations

import hashlib
import math
import re

from ..httpclient import describe_error, fetch

# A deliberately small sample of the passwords that dominate every credential
# dump. Presence here means "trivially guessable"; absence means nothing.
COMMON = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "111111",
    "1234567", "sunshine", "iloveyou", "princess", "admin", "welcome", "666666",
    "abc123", "football", "123123", "monkey", "654321", "!@#$%^&*", "charlie",
    "aa123456", "donald", "password1", "qwerty123", "letmein", "dragon",
    "baseball", "master", "superman", "trustno1", "shadow", "michael", "batman",
    "passw0rd", "starwars", "whatever", "zaq12wsx", "google", "hello", "freedom",
    "ninja", "azerty", "solo", "loveme", "flower", "hottie", "summer", "login",
    "corporate", "changeme", "secret", "test", "guest", "root", "toor",
    "correct horse battery staple",
}

LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})

KEYBOARD_RUNS = ("qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx", "poiuy", "yuiop", "hjkl")

PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(.)\1+$"), "a single repeated character"),
    (re.compile(r"(.)\1{3,}"), "four or more repeats of one character"),
    (re.compile(r"(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321)"), "a numeric run"),
    (re.compile(r"(abc|bcd|cde|def|efg|xyz)", re.I), "an alphabetic run"),
    (re.compile(r"(19|20)\d{2}$"), "a trailing year"),
    (re.compile(r"^[A-Z][a-z]+\d{1,4}[!@#$]?$"), "the Capital+word+digits+symbol shape that composition rules produce"),
    (re.compile(r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)", re.I), "a month name"),
    (re.compile(r"(spring|summer|autumn|fall|winter)", re.I), "a season name — the classic 90-day-rotation tell"),
)


def normalise(password: str) -> str:
    """Strip the substitutions crackers reverse for free."""
    return password.lower().translate(LEET)


def pool_entropy_bits(password: str) -> float:
    pool = (
        (26 if re.search(r"[a-z]", password) else 0)
        + (26 if re.search(r"[A-Z]", password) else 0)
        + (10 if re.search(r"\d", password) else 0)
        + (33 if re.search(r"[^A-Za-z0-9]", password) else 0)
    )
    return math.log2(pool) * len(password) if pool else 0.0


def guessability(password: str) -> tuple[str, list[str]]:
    """Return (verdict, reasons). Verdict is the number that actually matters."""
    reasons: list[str] = []
    normalised = normalise(password)
    stripped = re.sub(r"[^a-z]", "", normalised)

    if normalised in COMMON or stripped in COMMON:
        reasons.append("appears in the top-of-list common password set bundled with this tool")
    for base in COMMON:
        if len(base) >= 5 and base in normalised and base != normalised:
            reasons.append(f"is built around the common base word '{base}'")
            break
    for run in KEYBOARD_RUNS:
        if run in normalised:
            reasons.append(f"contains the keyboard run '{run}'")
            break
    for pattern, label in PATTERNS:
        if pattern.search(password):
            reasons.append(f"contains {label}")

    if reasons:
        verdict = "🔴 TRIVIALLY GUESSABLE" if len(reasons) >= 2 else "🟠 PREDICTABLE"
    elif len(password) < 12:
        verdict = "🟠 PREDICTABLE"
        reasons.append("is under 12 characters, which is within reach of offline GPU cracking")
    else:
        verdict = "🟢 NO KNOWN WEAK PATTERN"
    return verdict, reasons


async def _hibp(password: str) -> str:
    """Check Have I Been Pwned using k-anonymity: only 5 hex chars leave the host."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 — HIBP protocol requires SHA-1
    prefix, suffix = digest[:5], digest[5:]
    try:
        response, _ = await fetch(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
        )
    except Exception as exc:  # noqa: BLE001
        return "### Breach check\n\n" + describe_error(exc) + "\n"

    if response.status_code != 200:
        return f"### Breach check\n\n⚠️ HIBP returned HTTP {response.status_code}.\n"

    for line in response.text.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate == suffix:
            try:
                seen = int(count)
            except ValueError:
                seen = 0
            return (
                "### Breach check\n\n"
                f"🔴 **Found in {seen:,} known breach records.** This password is in public "
                "cracking wordlists. Length and complexity are irrelevant now — it must be "
                "changed everywhere it was used.\n"
            )
    return (
        "### Breach check\n\n"
        "🟢 Not present in the Have I Been Pwned corpus.\n\n"
        "> Absence is weak evidence. HIBP only knows about breaches that were "
        "published and ingested.\n"
    )


async def password_strength(password: str, check_breaches: bool = False) -> str:
    """Assess a password against NIST SP 800-63B, leading with guessability.

    Reports whether the password matches known-weak patterns, its length and
    character mix, and a pool-entropy figure explicitly labelled as an upper
    bound rather than a strength measure. Optionally checks Have I Been Pwned
    using k-anonymity, which sends only the first five hex characters of the
    password's SHA-1 hash and never the password itself.

    Args:
        password: The password to assess.
        check_breaches: If true, query Have I Been Pwned via k-anonymity.
            Off by default — turn it on deliberately, not habitually.
    """
    length = len(password)
    if length == 0:
        return "❌ Empty input."

    classes = {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "symbols": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    bits = pool_entropy_bits(password)
    verdict, reasons = guessability(password)

    privacy = (
        "the password is analysed locally and never transmitted"
        if not check_breaches
        else "the password itself is never transmitted; only the first 5 hex characters "
        "of its SHA-1 hash are sent to the HIBP range API (k-anonymity)"
    )

    out = "## Password assessment\n\n"
    out += f"> 🔒 Privacy: {privacy}. It is not written to the audit log.\n\n"
    out += f"### Verdict: {verdict}\n\n"
    if reasons:
        out += "This password " + "; it ".join(reasons) + ".\n\n"

    out += "| Field | Value |\n|---|---|\n"
    out += f"| Length | {length} characters |\n"
    out += f"| Character classes | {sum(classes.values())}/4 — " + ", ".join(
        f"{'✅' if v else '❌'} {k}" for k, v in classes.items()
    ) + " |\n"
    out += f"| Pool entropy (upper bound) | {bits:.0f} bits |\n\n"

    out += (
        f"> ⚠️ About that {bits:.0f} bits: it is `log2(charset) x length`, which is only a "
        "true strength measure for passwords generated uniformly at random. For a "
        "human-chosen password it is an upper bound and usually a wild one — "
        "`P@ssw0rd123` scores 72 bits by this formula and falls to a wordlist in "
        "under a second. Read the verdict above, not this number.\n\n"
    )

    if check_breaches:
        out += await _hibp(password) + "\n"

    out += "### What NIST SP 800-63B actually requires\n\n"
    out += "- Minimum 8 characters; allow at least 64 so passphrases are usable.\n"
    out += "- Screen candidates against breach corpora and dictionaries — this is the control that matters.\n"
    out += "- Do **not** impose composition rules; they push users toward `Summer2026!`.\n"
    out += "- Do **not** force periodic rotation. Rotate on evidence of compromise.\n"
    out += "- Allow all printable characters, including spaces and Unicode.\n"
    out += "- Pair with phishing-resistant MFA. Passkeys remove the password from the threat model entirely.\n\n"

    if length < 8:
        out += "❌ Below the 8-character NIST floor.\n"
    elif verdict.startswith("🔴") or verdict.startswith("🟠"):
        out += "➡️ Replace it. Use a manager-generated random string, or a 5+ word diceware passphrase.\n"
    else:
        out += "➡️ No weak pattern detected here, but that is not a guarantee. Uniqueness per site and MFA matter more.\n"

    return out
