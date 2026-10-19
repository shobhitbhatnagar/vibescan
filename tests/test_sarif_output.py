"""VS-2 SARIF serialization against the pinned official OASIS schema."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft4Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import sarif_output  # noqa: E402

SCHEMA_BYTES = (ROOT / "tests/schemas/sarif-schema-2.1.0.json").read_bytes()
assert hashlib.sha256(SCHEMA_BYTES).hexdigest() == "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
SCHEMA = json.loads(SCHEMA_BYTES)
VALIDATOR = Draft4Validator(SCHEMA, format_checker=FormatChecker())


def finding(**updates):
    item = {"category": "injection", "severity": "high", "confidence": "low",
            "title": "Synthetic unsafe call", "evidenceExcerpt": "PRIVATE_TEST_VALUE",
            "filePath": "src/café.py", "lineStart": 7, "lineEnd": 8,
            "fingerprint": "a" * 16, "scanner": "opengrep", "ruleId": "unsafe-eval"}
    item.update(updates)
    return item


class SarifOutputTests(unittest.TestCase):
    def valid(self, findings, summary):
        document = sarif_output.serialize(findings, summary, "0.3.0")
        VALIDATOR.validate(document)
        return document

    def test_empty_and_partial_coverage_remain_distinct(self):
        for status in ("complete", "partial", "failed"):
            doc = self.valid([], {"scanStatus": status, "enginesRan": ["gitleaks"],
                                  "degradedScanners": ["opengrep"],
                                  "toolchain": {"lockfile": "absent", "verifyMode": "strict",
                                                "engines": {"gitleaks": {"pinned": "v8.30.1", "status": "verified"}},
                                                "sast": {"path": "/private/engine"}}})
            run = doc["runs"][0]
            self.assertEqual(run["properties"]["scanStatus"], status)
            self.assertEqual(run["results"], [])
            self.assertNotIn("/private/engine", json.dumps(doc))
            self.assertEqual(run["properties"]["toolchainEngines"]["gitleaks"]["pinned"], "v8.30.1")

    def test_multiple_engines_preserve_rules_fingerprints_and_safe_location(self):
        doc = self.valid([finding(), finding(scanner="gitleaks", category="secret_exposure",
                                             severity="critical", filePath="src/secret.py",
                                             fingerprint="b" * 16)],
                         {"scanStatus": "complete", "enginesRan": ["opengrep", "gitleaks"],
                          "degradedScanners": []})
        run = doc["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual(run["results"][0]["ruleId"],
                         "vibescan/opengrep/" + sarif_output._rule_suffix("unsafe-eval", "injection"))
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/caf%C3%A9.py")
        self.assertEqual(run["results"][0]["partialFingerprints"]["vibescan/v1"], "a" * 16)
        self.assertEqual(run["results"][1]["level"], "error")

    def test_toolchain_rule_metadata_preserves_finding_rule_descriptors(self):
        doc = self.valid([finding()], {"scanStatus": "complete",
                                        "toolchain": {"rules": {"pinnedCommit": "a" * 12,
                                                                "actualCommit": "a" * 12,
                                                                "status": "verified"}}})
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"],
                         "vibescan/opengrep/" + sarif_output._rule_suffix("unsafe-eval", "injection"))
        self.assertEqual(run["properties"]["toolchainRules"]["status"], "verified")

    def test_unsafe_locations_are_omitted_without_losing_findings(self):
        for path in ("../secret.py", "/private/secret.py", "C:\\secret.py", "src/../secret.py",
                     "https://private.example/path", "src//bad.py", "src/\x00bad.py"):
            with self.subTest(path=path):
                result = self.valid([finding(filePath=path, lineStart=-2)],
                                    {"scanStatus": "partial"})["runs"][0]["results"][0]
                self.assertNotIn("locations", result)
        no_line = self.valid([finding(filePath="src/okay.py", lineStart=None, lineEnd=None)],
                             {"scanStatus": "complete"})["runs"][0]["results"][0]
        self.assertNotIn("region", no_line["locations"][0]["physicalLocation"])

    def test_titles_evidence_and_unknown_metadata_never_leak(self):
        marker = "PRIVATE_TEST_VALUE"
        doc = self.valid([finding(title=marker, evidenceExcerpt=marker,
                                  scanner=marker, category=marker, fingerprint=marker,
                                  ruleId=marker)],
                         {"scanStatus": "partial", "enginesRan": [marker],
                          "toolchain": {"path": marker, "verifyMode": marker}})
        self.assertNotIn(marker, json.dumps(doc))
        self.assertEqual(doc["runs"][0]["properties"]["enginesRan"], [])

    def test_untrusted_rule_and_toolchain_labels_never_copy_key_shaped_values(self):
        marker = "AKIA" + "ABCDEFGHIJKLMNOP"
        doc = self.valid([finding(ruleId=marker), finding(ruleId="unsafe-eval")],
                         {"scanStatus": "complete", "toolchain": {
                             "engines": {"gitleaks": {"pinned": marker, "status": marker}},
                             "rules": {"pinnedCommit": marker, "actualCommit": marker,
                                       "status": marker}}})
        encoded = json.dumps(doc)
        self.assertNotIn(marker, encoded)
        self.assertNotIn(marker.lower(), encoded)
        self.assertEqual(doc["runs"][0]["properties"]["toolchainEngines"]["gitleaks"],
                         {"pinned": "unknown", "status": "unknown"})
        self.assertEqual(len(doc["runs"][0]["tool"]["driver"]["rules"]), 2)

    def test_normalization_keeps_json_and_writes_valid_sarif(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "target"; target.mkdir()
            raw = target / ".vibescan/raw"; raw.mkdir(parents=True)
            (raw / "gitleaks.json").write_text("[]")
            (raw / "sast.sarif").write_text('{"runs":[]}')
            (raw / "osv.json").write_text('{"status":"complete","findings":[]}')
            subprocess.run([sys.executable, str(ROOT / "scripts/normalize.py"), str(target), str(raw), "", "", "gitleaks,opengrep,osv"],
                           check=True, capture_output=True, text=True)
            json_result = json.loads((target / ".vibescan/findings.json").read_text())
            sarif_result = json.loads((target / ".vibescan/findings.sarif").read_text())
            self.assertEqual(json_result["summary"]["scanStatus"], "complete")
            self.assertEqual(json_result["findings"], [])
            self.assertEqual(sarif_result["runs"][0]["properties"]["scanStatus"], "complete")
            VALIDATOR.validate(sarif_result)

    def test_relative_engine_location_survives_normalization(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "target"; target.mkdir()
            raw = target / ".vibescan/raw"; raw.mkdir(parents=True)
            (raw / "gitleaks.json").write_text("[]")
            (raw / "osv.json").write_text('{"status":"complete","findings":[]}')
            (raw / "sast.sarif").write_text(json.dumps({"runs": [{
                "tool": {"driver": {"name": "Synthetic", "rules": [{"id": "unsafe-eval"}]}},
                "results": [{"ruleId": "unsafe-eval", "level": "error",
                             "message": {"text": "synthetic test"},
                             "locations": [{"physicalLocation": {
                                 "artifactLocation": {"uri": "src/relative.py"},
                                 "region": {"startLine": 3}}}]}]}]}))
            subprocess.run([sys.executable, str(ROOT / "scripts/normalize.py"), str(target), str(raw), "", "", "gitleaks,opengrep,osv"],
                           check=True, capture_output=True, text=True)
            normalized = json.loads((target / ".vibescan/findings.json").read_text())
            sarif = json.loads((target / ".vibescan/findings.sarif").read_text())
            self.assertEqual(normalized["findings"][0]["filePath"], "src/relative.py")
            self.assertEqual(sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/relative.py")
            VALIDATOR.validate(sarif)


if __name__ == "__main__":
    unittest.main()
