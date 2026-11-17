# phishcheck

Offline phishing indicator checker for URLs and pasted email headers.
Pure Python standard library, no dependencies, no network code: it never
fetches the link, resolves a name, or sends anything anywhere.

## What it does

Give it a suspicious URL, the full headers of a suspicious email, or both.
It checks visible indicators and reports them with a heuristic score from
0 to 100:

- **0-29 LOW INDICATORS** - none of the checked tricks were seen
- **30-59 SUSPICIOUS** - some indicators matched
- **60-100 HIGH RISK** - several strong indicators matched

### URL checks

- Lookalike domains: brand names inside unrelated domains or subdomains
  (`paypal.com.secure-check.example`), leetspeak imitations (`paypa1`),
  and mixed-script homoglyphs (Cyrillic/Greek letters mixed with Latin)
- Punycode hosts (`xn--`), shown decoded
- Raw IP addresses as the host, including hex, integer, and zero-padded forms
- The `@` userinfo trick (`https://trusted.com@evil.example/`)
- Suspicious and free TLDs, known URL shorteners, missing HTTPS,
  unusual ports, deep subdomain nesting, very long URLs,
  percent-encoded hostnames, dangerous `data:`/`javascript:` style schemes

### Email header checks

- SPF, DKIM, and DMARC results from `Authentication-Results`
- From vs Return-Path and From vs Reply-To domain mismatches
- Display-name spoofing (a name or brand that disagrees with the real
  sender address), including brands claimed from free webmail accounts
- Urgency wording and generic greetings in the subject

## Usage

```bash
python3 phishcheck.py --url 'https://paypa1-secure.example/login'
python3 phishcheck.py --headers suspicious-headers.txt
cat suspicious-headers.txt | python3 phishcheck.py --headers -
python3 phishcheck.py --url 'https://example.com' --json
```

To copy full headers from common mail clients: Gmail - "Show original";
Outlook - "View message source" / message headers in properties.

Exit codes: 0 = low indicators, 1 = suspicious, 2 = high risk or a usage
error, so the tool is easy to wire into scripts.

## Honest limits

- **Heuristic, not a verdict.** A low score is not proof a link is safe -
  a fresh phishing domain with no visible tricks scores zero. A high score
  is not proof of malice either. When it matters, verify through a channel
  you already trust.
- **No network means no live data.** It cannot check domain age, blocklists,
  TLS certificates, or where a shortener actually points.
- **Curated lists.** The brand, TLD, shortener, and wording lists are small
  and hand-picked. They catch common cases and miss uncommon ones.
- **Approximate domains.** Without the Public Suffix List, the registrable
  domain is estimated with a short list of common two-label suffixes.
- **Header checks need the real headers.** Forwarded messages usually lose
  the original `Authentication-Results`; paste "show original" output.

## Development

```bash
python3 -m unittest discover -s tests
```

The test suite covers each indicator, the scoring bands, the CLI and its
exit codes, and a guard that fails if any analysis path touches the
network. All test data is synthetic.

## License

MIT - see LICENSE.
