#!/usr/bin/env python3
"""Tests for phishcheck. All data is synthetic: reserved example domains and
invented addresses, no real messages or credentials."""

import io
import json
import os
import socket
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import phishcheck as pc  # noqa: E402


def keys(result):
    return {f["check"] for f in result["findings"]}


CLEAN_HEADERS = """\
Return-Path: <news@service.example>
From: Example Service <news@service.example>
Reply-To: support@service.example
Subject: Your March statement is ready
Authentication-Results: mx.example; spf=pass smtp.mailfrom=service.example; dkim=pass header.d=service.example; dmarc=pass header.from=service.example
Received: by mx.example with ESMTPS id abc123
Message-ID: <m1@service.example>
"""

PHISH_HEADERS = """\
Return-Path: <bounce@mail.evil-example.tk>
From: "PayPal Support" <paypal-support@evil-example.tk>
Reply-To: steal@collector.example
Subject: URGENT: your account has been suspended, act now within 24 hours
Authentication-Results: mx.example; spf=fail smtp.mailfrom=evil-example.tk; dkim=fail header.d=evil-example.tk; dmarc=fail header.from=evil-example.tk
Received: from mail.evil-example.tk by mx.example
Message-ID: <m2@evil-example.tk>
"""


class UrlAnalysisTests(unittest.TestCase):
    def test_clean_https_url_has_no_findings(self):
        r = pc.analyze_url("https://www.example.com/about/team")
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["host"], "www.example.com")
        self.assertEqual(r["registrable_domain"], "example.com")

    def test_legit_brand_domain_not_flagged(self):
        for url in ("https://www.paypal.com/signin",
                    "https://accounts.google.com/login",
                    "https://github.com"):
            r = pc.analyze_url(url)
            self.assertNotIn("brand_spoof", keys(r), url)

    def test_http_scheme_flagged(self):
        r = pc.analyze_url("http://example.com/login")
        self.assertIn("no_https", keys(r))

    def test_missing_scheme_skips_https_check(self):
        r = pc.analyze_url("example.com/login")
        self.assertNotIn("no_https", keys(r))
        self.assertTrue(any("scheme" in n for n in r["notes"]))

    def test_punycode_flagged(self):
        r = pc.analyze_url("https://xn--pypal-4ve.com/")
        self.assertIn("punycode", keys(r))

    def test_cyrillic_homoglyph_flagged(self):
        # 'а' (Cyrillic) mixed with ASCII letters in one label.
        r = pc.analyze_url("https://www.раypal.example.com/")
        self.assertIn("homoglyph", keys(r))

    def test_ip_host_forms_flagged(self):
        for url in ("https://192.0.2.10/login",
                    "http://0xC000020A/",
                    "http://3221225994/",
                    "http://0300.0.02.012/"):
            r = pc.analyze_url(url)
            self.assertIn("ip_host", keys(r), url)

    def test_userinfo_at_flagged(self):
        r = pc.analyze_url("https://example.com@evil.example/login")
        self.assertIn("userinfo", keys(r))
        self.assertEqual(r["host"], "evil.example")

    def test_suspicious_tld_flagged(self):
        r = pc.analyze_url("https://login.example.tk/")
        self.assertIn("suspicious_tld", keys(r))

    def test_shortener_flagged(self):
        r = pc.analyze_url("https://bit.ly/3abc")
        self.assertIn("shortener", keys(r))

    def test_brand_in_subdomain_flagged(self):
        r = pc.analyze_url("https://paypal.com.secure-check.example/login")
        self.assertIn("brand_spoof", keys(r))

    def test_brand_hyphenated_domain_flagged(self):
        r = pc.analyze_url("https://secure-paypal.example/")
        self.assertIn("brand_spoof", keys(r))

    def test_leetspeak_brand_flagged(self):
        r = pc.analyze_url("https://paypa1.example/")
        self.assertIn("brand_spoof", keys(r))
        detail = [f for f in r["findings"] if f["check"] == "brand_spoof"][0]
        self.assertIn("look-alike", detail["detail"])

    def test_many_subdomains_flagged(self):
        r = pc.analyze_url("https://a.b.c.example.com/")
        self.assertIn("many_subdomains", keys(r))

    def test_unusual_port_flagged(self):
        r = pc.analyze_url("https://example.com:8443/")
        self.assertIn("unusual_port", keys(r))

    def test_long_url_flagged(self):
        r = pc.analyze_url("https://example.com/" + "a" * 130)
        self.assertIn("long_url", keys(r))

    def test_dangerous_scheme_flagged(self):
        r = pc.analyze_url("javascript:alert(1)")
        self.assertIn("dangerous_scheme", keys(r))

    def test_multi_label_suffix_handled(self):
        r = pc.analyze_url("https://login.example.co.uk/")
        self.assertEqual(r["registrable_domain"], "example.co.uk")
        self.assertEqual(r["findings"], [])

    def test_empty_and_broken_urls_do_not_crash(self):
        self.assertIn("error", pc.analyze_url(""))
        self.assertIn("error", pc.analyze_url("https://"))
        self.assertIn("error", pc.analyze_url("not a url with spaces only host"))
        r = pc.analyze_url("https://example.com:badport/")
        self.assertTrue(any("port" in n for n in r["notes"]))

    def test_encoded_host_flagged(self):
        r = pc.analyze_url("https://examp%6ce.com/")
        self.assertIn("encoded_host", keys(r))


class HeaderAnalysisTests(unittest.TestCase):
    def test_clean_headers_have_no_findings(self):
        r = pc.analyze_headers(CLEAN_HEADERS)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["from_domain"], "service.example")
        self.assertEqual(r["authentication"]["spf"], "pass")

    def test_phish_headers_flag_everything(self):
        r = pc.analyze_headers(PHISH_HEADERS)
        got = keys(r)
        self.assertIn("spf_fail", got)
        self.assertIn("dkim_fail", got)
        self.assertIn("dmarc_fail", got)
        self.assertIn("from_returnpath_mismatch", got)
        self.assertIn("replyto_mismatch", got)
        self.assertIn("display_spoof", got)
        self.assertIn("urgency_wording", got)

    def test_spf_softfail(self):
        r = pc.analyze_headers(CLEAN_HEADERS.replace("spf=pass", "spf=softfail"))
        self.assertIn("spf_softfail", keys(r))

    def test_dmarc_none(self):
        r = pc.analyze_headers(CLEAN_HEADERS.replace("dmarc=pass", "dmarc=none"))
        self.assertIn("dmarc_none", keys(r))

    def test_missing_auth_results_noted(self):
        text = "From: a@b.example\nSubject: hi\n"
        r = pc.analyze_headers(text)
        self.assertTrue(any("Authentication-Results" in n for n in r["notes"]))

    def test_display_name_email_mismatch(self):
        text = ("From: \"paypal@billing.example\" <random@other.example>\n"
                "Subject: notice\n")
        r = pc.analyze_headers(text)
        self.assertIn("display_spoof", keys(r))

    def test_freemail_claiming_brand(self):
        text = ("From: \"Netflix Billing\" <accountteam@gmail.com>\n"
                "Subject: payment failed\n")
        r = pc.analyze_headers(text)
        self.assertIn("freemail_brand", keys(r))

    def test_generic_greeting(self):
        text = "From: a@b.example\nSubject: Dear customer, please review\n"
        r = pc.analyze_headers(text)
        self.assertIn("generic_greeting", keys(r))

    def test_empty_and_fromless_headers(self):
        self.assertIn("error", pc.analyze_headers(""))
        self.assertIn("error", pc.analyze_headers("Subject: hi\n"))


class ScoringTests(unittest.TestCase):
    def test_score_caps_at_100(self):
        score, findings, _ = pc.score_findings(
            pc.analyze_url("https://xn--pypal-4ve.tk@192.0.2.1:8443/"),
            pc.analyze_headers(PHISH_HEADERS))
        self.assertEqual(score, 100)
        self.assertEqual(pc.verdict_for(score), "HIGH RISK")

    def test_verdict_bands(self):
        self.assertEqual(pc.verdict_for(0), "LOW INDICATORS")
        self.assertEqual(pc.verdict_for(29), "LOW INDICATORS")
        self.assertEqual(pc.verdict_for(30), "SUSPICIOUS")
        self.assertEqual(pc.verdict_for(59), "SUSPICIOUS")
        self.assertEqual(pc.verdict_for(60), "HIGH RISK")

    def test_duplicate_checks_counted_once(self):
        f = {"check": "punycode", "points": 30, "detail": "x"}
        score, findings, _ = pc.score_findings({"findings": [f, dict(f)]})
        self.assertEqual(score, 30)
        self.assertEqual(len(findings), 1)


class CliTests(unittest.TestCase):
    def run_cli(self, argv, stdin_text=""):
        out = io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
        try:
            with redirect_stdout(out):
                code = pc.main(argv)
        finally:
            sys.stdin = old_stdin
        return code, out.getvalue()

    def test_clean_url_exit_0(self):
        code, out = self.run_cli(["--url", "https://example.com"])
        self.assertEqual(code, 0)
        self.assertIn("LOW INDICATORS", out)
        self.assertIn("phishcheck", out)

    def test_phish_url_exit_2(self):
        code, out = self.run_cli(["--url", "https://paypa1-secure.tk@192.0.2.1/"])
        self.assertEqual(code, 2)
        self.assertIn("HIGH RISK", out)

    def test_headers_from_stdin(self):
        code, out = self.run_cli(["--headers", "-"], stdin_text=PHISH_HEADERS)
        self.assertEqual(code, 2)
        self.assertIn("HIGH RISK", out)

    def test_headers_from_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(CLEAN_HEADERS)
            path = fh.name
        try:
            code, out = self.run_cli(["--headers", path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 0)

    def test_missing_headers_file_returns_2(self):
        code = pc.main(["--headers", "/nonexistent/nope.txt"])
        self.assertEqual(code, 2)

    def test_json_output_is_valid(self):
        code, out = self.run_cli(
            ["--url", "https://paypa1.example", "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "SUSPICIOUS")
        self.assertIn("disclaimer", data)
        self.assertTrue(any(f["check"] == "brand_spoof"
                            for f in data["findings"]))

    def test_no_arguments_errors(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                pc.main([])


class NoNetworkTests(unittest.TestCase):
    def test_analysis_never_touches_the_network(self):
        class Boom:
            def __init__(self, *a, **k):
                raise AssertionError("network access attempted")

        real_socket, real_create = socket.socket, socket.create_connection
        socket.socket = Boom
        socket.create_connection = Boom
        try:
            pc.analyze_url("https://paypa1.example/login")
            pc.analyze_headers(PHISH_HEADERS)
            with redirect_stdout(io.StringIO()):
                code = pc.main(["--url", "https://example.com", "--json"])
        finally:
            socket.socket = real_socket
            socket.create_connection = real_create
        self.assertEqual(code, 0)


class InternalsTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(pc.registrable_domain("example.com"), "example.com")
        self.assertEqual(pc.registrable_domain("a.b.example.com"),
                         "example.com")
        self.assertEqual(pc.registrable_domain("a.b.example.co.uk"),
                         "example.co.uk")
        self.assertEqual(pc.registrable_domain("a.b.example.com.sa"),
                         "example.com.sa")

    def test_decode_host(self):
        self.assertEqual(pc.decode_host("xn--pypal-4ve.com"),
                         "p\u0430ypal.com")  # Cyrillic 'a'

    def test_leet_normalize(self):
        self.assertEqual(pc._leet_normalize("P4yp4-1"), "paypal")


class TerminalSafetyTests(unittest.TestCase):
    EVIL_HEADERS = CLEAN_HEADERS.replace(
        "From: Example Service <news@service.example>",
        "From: Bad\x1b[2J\x1b[31m Actor <news@service.example>")

    def test_render_text_strips_ansi_from_header_fields(self):
        r = pc.analyze_headers(self.EVIL_HEADERS)
        out = pc.render_text(None, r, 0, [], [])
        self.assertNotIn("\x1b", out)
        self.assertIn("bad", out)

    def test_render_text_strips_ansi_from_url_fields(self):
        url_result = {"input": "https://example.com/\x1b[2J",
                      "host": "example.com",
                      "registrable_domain": "example.com"}
        out = pc.render_text(url_result, None, 0, [], [])
        self.assertNotIn("\x1b", out)

    def test_untrusted_text_cannot_inject_report_lines(self):
        findings = [{"points": 10, "check": "x",
                     "detail": "a\r\nScore: 0/100 -> LOW INDICATORS"}]
        out = pc.render_text(None, None, 10, findings, [])
        score_lines = [l for l in out.splitlines() if l.startswith("Score:")]
        self.assertEqual(len(score_lines), 1)
        self.assertIn("10/100", score_lines[0])


if __name__ == "__main__":
    unittest.main()
