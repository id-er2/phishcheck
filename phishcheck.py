#!/usr/bin/env python3
"""phishcheck - offline phishing indicator checker for URLs and email headers.

Reads a URL and/or pasted email headers and reports common phishing
indicators with a heuristic risk score. It makes no network requests:
nothing is fetched, resolved, or sent. All checks are local string and
pattern analysis.

The score is a heuristic. A low score is not proof that a link or message
is safe, and a high score is not proof of malice. It is a second pair of
eyes, not a verdict.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from urllib.parse import urlsplit

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Curated lists. These are deliberately small and honest: they catch common
# cases and will miss uncommon ones. README documents this limitation.
# --------------------------------------------------------------------------

# TLDs that appear in abuse reports far more often than in legitimate mail.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",          # free Freenom domains
    "zip", "mov", "top", "xyz", "click", "link", "work", "date",
    "loan", "racing", "download", "stream", "win", "bid", "cam",
    "rest", "quest", "beauty", "hair", "mom", "cfd", "sbs", "icu",
}

# Well-known URL shorteners. A short link hides its destination.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "s.id", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "t.ly", "tiny.cc", "cli.re", "v.gd", "qr.ae",
}

# Commonly impersonated brands mapped to their real domains. Small on
# purpose; extending it is easy but it will never be complete.
BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com",
                  "outlook.com", "microsoftonline.com", "windows.net"},
    "apple": {"apple.com", "icloud.com", "itunes.com"},
    "google": {"google.com", "accounts.google.com", "gmail.com",
               "googleapis.com", "youtube.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.sa",
               "amazon.ae", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "dropbox": {"dropbox.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "stcpay": {"stcpay.com", "stcpay.com.sa"},
    "alrajhi": {"alrajhibank.com.sa", "alrajhibank.com"},
}

# Free webmail providers. Legitimate companies do not send account
# notices from these.
FREEMAIL = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
    "proton.me", "protonmail.com", "icloud.com", "mail.com", "gmx.com",
    "yandex.com", "zoho.com", "live.com", "msn.com",
}

# Two-label public suffixes seen often enough to special-case. Without the
# full Public Suffix List this is an approximation; the README says so.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "or.jp", "ne.jp",
    "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa",
    "com.br", "com.cn", "com.tw", "com.hk", "com.sg", "com.mx",
    "co.in", "co.za", "co.nz", "com.tr", "com.ar", "com.pl",
    "com.ae", "com.eg", "com.pk", "com.my", "com.ph", "co.kr",
}

# Pressure wording common in phishing subjects (English, lowercase).
URGENCY_WORDS = [
    "urgent", "immediately", "immediate action", "action required",
    "verify your account", "confirm your identity", "account suspended",
    "has been suspended", "will be closed", "will be suspended",
    "unusual activity", "unauthorized", "final notice", "last warning",
    "24 hours", "48 hours", "password expires", "password expiring",
    "update your payment", "billing problem", "payment failed",
    "limited time", "act now", "don't ignore", "security alert",
]

# Generic greetings: real services usually address you by name.
GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear sir", "dear madam",
    "dear account holder", "dear valued", "dear client",
]

# Letters often swapped to imitate brand names.
LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                          "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"})

# Findings carry a weight and an explanation. Weights are heuristic.
WEIGHTS = {
    "dangerous_scheme": 60,
    "homoglyph": 40,
    "brand_spoof": 40,
    "ip_host": 35,
    "punycode": 30,
    "userinfo": 25,
    "display_spoof": 25,
    "dmarc_fail": 25,
    "spf_fail": 25,
    "dkim_fail": 20,
    "freemail_brand": 20,
    "suspicious_tld": 15,
    "shortener": 15,
    "from_returnpath_mismatch": 15,
    "replyto_mismatch": 15,
    "spf_softfail": 15,
    "no_https": 10,
    "many_subdomains": 10,
    "unusual_port": 10,
    "urgency_wording": 10,
    "generic_greeting": 10,
    "encoded_host": 10,
    "long_url": 5,
    "hyphenated_domain": 5,
    "dmarc_none": 5,
}


class Finding:
    """One observed indicator."""

    __slots__ = ("key", "weight", "message")

    def __init__(self, key: str, message: str, weight: int | None = None):
        self.key = key
        self.weight = WEIGHTS[key] if weight is None else weight
        self.message = message

    def to_dict(self) -> dict:
        return {"check": self.key, "points": self.weight, "detail": self.message}


class Note:
    """Informational remark, no score impact."""

    __slots__ = ("message",)

    def __init__(self, message: str):
        self.message = message


# --------------------------------------------------------------------------
# Domain helpers
# --------------------------------------------------------------------------

def _decode_label(label: str) -> str:
    """Decode one IDNA/punycode label; return it unchanged on failure."""
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError, ValueError):
        return label


def decode_host(host: str) -> str:
    """IDNA-decode every label of a hostname."""
    return ".".join(_decode_label(l) for l in host.split("."))


def split_labels(host: str) -> list[str]:
    return [l for l in host.lower().strip(".").split(".") if l]


def registrable_domain(host: str) -> str:
    """Approximate the registrable domain without the Public Suffix List.

    Handles a small set of common two-label suffixes (co.uk, com.sa, ...);
    otherwise takes the last two labels.
    """
    labels = split_labels(host)
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def subdomain_labels(host: str) -> list[str]:
    """Labels left of the approximate registrable domain."""
    labels = split_labels(host)
    reg = registrable_domain(host)
    return labels[: len(labels) - len(reg.split("."))]


def _leet_normalize(text: str) -> str:
    """Lowercase, strip separators, undo common leetspeak swaps."""
    text = re.sub(r"[^a-z0-9$@]", "", text.lower())
    text = text.replace("rn", "m").replace("vv", "w")
    return text.translate(LEET_MAP)


def _looks_like_ip(host: str) -> str | None:
    """Return a description if the host is an IP literal, else None."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "standard IP address"
    except ValueError:
        pass
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", host):
        return "hexadecimal IP address"
    if re.fullmatch(r"\d+", host):
        try:
            if int(host) <= 0xFFFFFFFF:
                return "integer-encoded IPv4 address"
        except ValueError:
            pass
    parts = host.split(".")
    if (1 < len(parts) <= 4 and all(p.isdigit() for p in parts)
            and any(len(p) > 1 and p.startswith("0") for p in parts)):
        return "zero-padded (octal-style) IP address"
    return None


def _has_homoglyphs(text: str) -> bool:
    """Non-ASCII letters mixed with ASCII alphanumerics in the same label."""
    for label in text.split("."):
        has_ascii = any(c.isascii() and c.isalnum() for c in label)
        has_nonascii_letter = any(
            not c.isascii() and c.isalpha() for c in label
        )
        if has_ascii and has_nonascii_letter:
            return True
    return False


# --------------------------------------------------------------------------
# URL analysis
# --------------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    findings: list[Finding] = []
    notes: list[Note] = []

    raw = url.strip()
    if not raw:
        return {"input": url, "findings": [], "notes": ["Empty input."],
                "host": None, "error": "empty URL"}

    if re.match(r"(?i)^(data|javascript|vbscript):", raw):
        findings.append(Finding(
            "dangerous_scheme",
            "The input uses a data:/javascript: style scheme, which carries "
            "its payload inside the link itself."))
        return {"input": raw, "host": None,
                "findings": [f.to_dict() for f in findings], "notes": []}

    parse_target = raw if "://" in raw else "http://" + raw
    had_scheme = "://" in raw
    try:
        parts = urlsplit(parse_target)
    except ValueError as exc:
        return {"input": raw, "host": None, "findings": [],
                "notes": [], "error": f"could not parse URL: {exc}"}

    host = parts.hostname or ""
    if not host:
        return {"input": raw, "host": None, "findings": [],
                "notes": [], "error": "no host found in URL"}

    host = host.lower().strip(".")
    if any(c.isspace() for c in host):
        return {"input": raw, "host": None, "findings": [], "notes": [],
                "error": "the host contains whitespace, so this is not a "
                         "valid URL"}
    decoded_host = decode_host(host)
    reg = registrable_domain(decoded_host)
    tld = split_labels(decoded_host)[-1] if split_labels(decoded_host) else ""

    if not had_scheme:
        notes.append(Note("No scheme given; treated as http:// for parsing, "
                          "so the HTTPS check was skipped."))
    elif parts.scheme.lower() != "https":
        findings.append(Finding(
            "no_https",
            f"The scheme is '{parts.scheme.lower()}', not https. Credentials "
            "sent over plain http travel unencrypted."))

    if "%" in host:
        findings.append(Finding(
            "encoded_host",
            "The host contains percent-encoding, which is unusual and can "
            "hide the real characters."))

    if "@" in parts.netloc:
        findings.append(Finding(
            "userinfo",
            "The URL contains an '@' before the host. Everything before the "
            "'@' is ignored user info and can be made to look like a "
            "trusted name."))

    ip_kind = _looks_like_ip(host)
    if ip_kind:
        findings.append(Finding(
            "ip_host",
            f"The host is a {ip_kind} ({host}), not a domain name. "
            "Legitimate services almost never link to raw IPs."))

    if "xn--" in host:
        findings.append(Finding(
            "punycode",
            f"The host contains punycode (xn--), shown decoded as "
            f"'{decoded_host}'. Punycode can render foreign characters that "
            "imitate a familiar name."))

    if _has_homoglyphs(decoded_host):
        findings.append(Finding(
            "homoglyph",
            f"The host '{decoded_host}' mixes non-ASCII letters with ASCII "
            "in the same label, a classic lookalike-domain trick."))

    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding(
            "suspicious_tld",
            f"The top-level domain '.{tld}' is cheap or free and appears in "
            "abuse reports far more often than in legitimate use."))

    if reg in SHORTENERS:
        findings.append(Finding(
            "shortener",
            f"'{reg}' is a URL shortener. The real destination is hidden; "
            "expand it in a safe way before trusting it."))

    subs = subdomain_labels(decoded_host)
    if len(subs) >= 3:
        findings.append(Finding(
            "many_subdomains",
            f"The host has {len(subs)} subdomain levels "
            f"({'...' + '.'.join(split_labels(decoded_host)[-4:])}). Deep "
            "nesting is often used to push the real domain out of view."))

    try:
        port = parts.port
    except ValueError:
        port = None
        notes.append(Note("The port in the URL is malformed."))
    if port is not None and port not in (80, 443):
        findings.append(Finding(
            "unusual_port",
            f"The URL uses non-standard port {port}."))

    if len(raw) > 120:
        findings.append(Finding(
            "long_url",
            f"The URL is {len(raw)} characters long. Unusual length can be "
            "used to bury the real host or to stuff tracking and redirect "
            "parameters."))

    # Brand impersonation: brand name inside a domain that is not the
    # brand's own. Checks the registrable label and the subdomains once,
    # keeping the strongest single finding per brand.
    sld = split_labels(reg)[0] if split_labels(reg) else ""
    brand_hit = None
    for brand, domains in BRANDS.items():
        if reg in domains:
            continue  # the domain really belongs to the brand
        norm_sld = _leet_normalize(sld)
        norm_subs = [_leet_normalize(s) for s in subs]
        used_leet = False
        if brand in norm_sld and brand not in sld.lower().replace("-", ""):
            used_leet = True
        in_sld = brand in norm_sld or brand in sld.lower().replace("-", "")
        in_sub = any(brand in n for n in norm_subs)
        if not in_sld and not in_sub:
            continue
        where = f"the domain '{reg}'" if in_sld else "a subdomain"
        detail = (f"The name '{brand}' appears in {where}, but the actual "
                  f"domain is '{reg}', which is not a known {brand} domain.")
        if used_leet:
            detail += (" The spelling substitutes look-alike characters "
                       "(for example a digit for a letter).")
        brand_hit = Finding("brand_spoof", detail)
        break
    if brand_hit:
        findings.append(brand_hit)
    elif "-" in sld and len(sld) > 12:
        findings.append(Finding(
            "hyphenated_domain",
            f"The domain '{reg}' is long and hyphenated, a common shape for "
            "throwaway phishing domains."))

    return {
        "input": raw,
        "host": decoded_host,
        "registrable_domain": reg,
        "findings": [f.to_dict() for f in findings],
        "notes": [n.message for n in notes],
    }


# --------------------------------------------------------------------------
# Email header analysis
# --------------------------------------------------------------------------

_AUTH_RE = re.compile(
    r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE)


def _addr_domain(addr: str) -> str:
    """Domain part of an address, or '' when it has none."""
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].lower().strip(">")


def _domains_of(header_values: list[str]) -> list[str]:
    """(display, address, domain) for each address in the header values."""
    out = []
    for value in header_values:
        display, addr = parseaddr(value)
        if addr:
            out.append((display, addr.lower(), _addr_domain(addr)))
    return out


def analyze_headers(text: str) -> dict:
    findings: list[Finding] = []
    notes: list[Note] = []

    if not text.strip():
        return {"findings": [], "notes": [], "error": "empty headers"}

    msg = Parser(policy=policy.default).parsestr(text)

    froms = _domains_of(msg.get_all("from", []))
    if not froms:
        return {"findings": [], "notes": [], "error": "no From header found"}
    from_display, from_addr, from_domain = froms[0]

    return_paths = _domains_of(msg.get_all("return-path", []))
    reply_tos = _domains_of(msg.get_all("reply-to", []))
    subject = str(msg.get("subject", ""))

    # Authentication-Results ---------------------------------------------
    auth_headers = msg.get_all("authentication-results", [])
    auth = {}
    for header in auth_headers:
        for mech, result in _AUTH_RE.findall(str(header)):
            auth.setdefault(mech.lower(), result.lower())

    if not auth_headers:
        notes.append(Note(
            "No Authentication-Results header found. Some servers strip it; "
            "SPF/DKIM/DMARC could not be assessed from this copy."))
    else:
        spf = auth.get("spf")
        if spf == "fail":
            findings.append(Finding(
                "spf_fail",
                "SPF failed: the sending server is not authorized for the "
                "envelope sender's domain."))
        elif spf == "softfail":
            findings.append(Finding(
                "spf_softfail",
                "SPF softfail: the sending server is probably not authorized "
                "for the envelope sender's domain."))
        dkim = auth.get("dkim")
        if dkim == "fail":
            findings.append(Finding(
                "dkim_fail",
                "DKIM failed: the message signature did not verify, so the "
                "content or the claimed signer does not match."))
        dmarc = auth.get("dmarc")
        if dmarc == "fail":
            findings.append(Finding(
                "dmarc_fail",
                "DMARC failed: the From domain is not authenticated by SPF "
                "or DKIM alignment."))
        elif dmarc in ("none",) and "dmarc" in auth:
            findings.append(Finding(
                "dmarc_none",
                "DMARC reported 'none': the From domain has no effective "
                "DMARC enforcement."))

    # Address relationships -----------------------------------------------
    if return_paths:
        rp_domain = return_paths[0][2]
        if rp_domain and from_domain and rp_domain != from_domain:
            findings.append(Finding(
                "from_returnpath_mismatch",
                f"The From domain '{from_domain}' differs from the "
                f"Return-Path domain '{rp_domain}'. Bounces go somewhere "
                "other than where the message claims to be from."))

    if reply_tos:
        rt_domain = reply_tos[0][2]
        if rt_domain and from_domain and rt_domain != from_domain:
            findings.append(Finding(
                "replyto_mismatch",
                f"Replies go to '{rt_domain}' instead of the From domain "
                f"'{from_domain}'. Answers are steered to a different "
                "address than the one shown."))

    # Display name tricks ---------------------------------------------------
    if from_display:
        disp = from_display.strip()
        if "@" in disp:
            disp_domain = _addr_domain(disp)
            if disp_domain and disp_domain != from_domain:
                findings.append(Finding(
                    "display_spoof",
                    f"The display name shows '{disp}' but the real sender "
                    f"address is '{from_addr}'. The visible name and the "
                    "actual address disagree."))
        norm_disp = _leet_normalize(disp)
        for brand, domains in BRANDS.items():
            if brand in norm_disp and from_domain not in domains:
                w = None
                key = "display_spoof"
                if from_domain in FREEMAIL:
                    key = "freemail_brand"
                    detail = (f"The display name claims '{brand}' but the "
                              f"sender uses the free mail provider "
                              f"'{from_domain}'. Real {brand} mail does not "
                              "come from webmail addresses.")
                else:
                    detail = (f"The display name claims '{brand}' but the "
                              f"sender's domain is '{from_domain}', which is "
                              "not a known domain of that brand.")
                if not any(f.key in ("display_spoof", "freemail_brand")
                           for f in findings):
                    findings.append(Finding(key, detail, w))
                break

    # Subject pressure wording ----------------------------------------------
    subject_lower = subject.lower()
    hits = [w for w in URGENCY_WORDS if w in subject_lower]
    if hits:
        findings.append(Finding(
            "urgency_wording",
            "The subject uses pressure wording: "
            + ", ".join(f"'{h}'" for h in hits[:4])
            + ". Urgency is the standard way phishing stops you thinking."))
    greets = [g for g in GENERIC_GREETINGS if g in subject_lower]
    if greets:
        findings.append(Finding(
            "generic_greeting",
            "The subject greets generically ("
            + ", ".join(f"'{g}'" for g in greets)
            + "). Real services usually address you by name."))

    hops = len(msg.get_all("received", []))
    notes.append(Note(f"The message passed through {hops} recorded "
                      "Received hop(s)."))

    return {
        "from": from_addr,
        "from_domain": from_domain,
        "return_path_domain": return_paths[0][2] if return_paths else "",
        "reply_to_domain": reply_tos[0][2] if reply_tos else "",
        "subject": subject,
        "authentication": auth,
        "findings": [f.to_dict() for f in findings],
        "notes": [n.message for n in notes],
    }


# --------------------------------------------------------------------------
# Scoring and reporting
# --------------------------------------------------------------------------

def score_findings(*sections: dict) -> tuple[int, list[dict], list[str]]:
    """Combine findings from analysis sections into one capped score."""
    seen = set()
    findings, notes = [], []
    for section in sections:
        for f in section.get("findings", []):
            if f["check"] in seen:
                continue
            seen.add(f["check"])
            findings.append(f)
        notes.extend(section.get("notes", []))
    score = min(100, sum(f["points"] for f in findings))
    return score, findings, notes


def verdict_for(score: int) -> str:
    if score >= 60:
        return "HIGH RISK"
    if score >= 30:
        return "SUSPICIOUS"
    return "LOW INDICATORS"


EXIT_CODES = {"LOW INDICATORS": 0, "SUSPICIOUS": 1, "HIGH RISK": 2}

DISCLAIMER = ("This is a heuristic check of visible indicators only. A low "
              "score is not proof that a link or message is safe; a high "
              "score is not proof of malice. When it matters, verify through "
              "a channel you already trust.")


def render_text(url_result: dict | None, header_result: dict | None,
                score: int, findings: list[dict], notes: list[str]) -> str:
    lines = [f"phishcheck {VERSION} - offline phishing indicator check", ""]
    if url_result is not None:
        if url_result.get("error"):
            lines.append(f"URL: {url_result.get('input', '')}")
            lines.append(f"  could not analyze: {url_result['error']}")
        else:
            lines.append(f"URL: {url_result['input']}")
            lines.append(f"  host: {url_result['host']}"
                         f"  (registrable: {url_result['registrable_domain']})")
        lines.append("")
    if header_result is not None:
        if header_result.get("error"):
            lines.append(f"Headers: could not analyze: {header_result['error']}")
        else:
            lines.append(f"Headers: From {header_result['from']}"
                         f"  Subject: {header_result['subject']!r}")
        lines.append("")
    if findings:
        lines.append("Findings:")
        for f in sorted(findings, key=lambda x: -x["points"]):
            lines.append(f"  [{f['points']:>2} pts] {f['detail']}")
    else:
        lines.append("Findings: none of the checked indicators matched.")
    lines.append("")
    if notes:
        for n in notes:
            lines.append(f"note: {n}")
        lines.append("")
    verdict = verdict_for(score)
    lines.append(f"Score: {score}/100 -> {verdict}")
    lines.append("")
    lines.append(DISCLAIMER)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishcheck",
        description="Offline phishing indicator checker for URLs and pasted "
                    "email headers. Makes no network requests.")
    p.add_argument("--url", help="URL or domain to analyze")
    p.add_argument("--headers",
                   help="path to a file with pasted email headers, or '-' "
                        "to read them from standard input")
    p.add_argument("--json", action="store_true",
                   help="print machine-readable JSON instead of text")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.url and not args.headers:
        build_parser().error("give --url and/or --headers")

    url_result = analyze_url(args.url) if args.url else None

    header_result = None
    if args.headers:
        if args.headers == "-":
            header_text = sys.stdin.read()
        else:
            try:
                with open(args.headers, "r", encoding="utf-8",
                          errors="replace") as fh:
                    header_text = fh.read()
            except OSError as exc:
                print(f"phishcheck: cannot read {args.headers}: {exc}",
                      file=sys.stderr)
                return 2
        header_result = analyze_headers(header_text)

    sections = [s for s in (url_result, header_result) if s is not None]
    score, findings, notes = score_findings(*sections)
    verdict = verdict_for(score)

    if args.json:
        out = {
            "version": VERSION,
            "score": score,
            "verdict": verdict,
            "findings": findings,
            "notes": notes,
            "url": url_result,
            "headers": header_result,
            "disclaimer": DISCLAIMER,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(render_text(url_result, header_result, score, findings, notes))

    return EXIT_CODES[verdict]


if __name__ == "__main__":
    raise SystemExit(main())
