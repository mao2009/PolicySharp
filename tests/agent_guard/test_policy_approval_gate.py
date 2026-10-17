"""Git-level tests for the PolicySharp protected-change approval contract."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/check-policy-trust-boundary.sh"
MANIFEST = ROOT / ".policysharp/protected-paths.txt"


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"),
                     "requires git and bash")
class PolicyApprovalGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / ".policysharp").mkdir()
        shutil.copy2(MANIFEST, self.repo / ".policysharp/protected-paths.txt")
        self.git("init", "-q")
        self.git("config", "user.name", "fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "README.md").write_text("baseline\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True, text=True, capture_output=True,
        )

    def gate(self, label=False, independent=False):
        env = os.environ.copy()
        env["POLICY_APPROVED"] = str(label).lower()
        env["POLICY_SOLO_APPROVED"] = str(independent).lower()
        return subprocess.run(
            ["bash", str(GATE), self.base, "HEAD"],
            cwd=self.repo, env=env, check=False, text=True, capture_output=True,
        )

    def change(self, filename):
        target = self.repo / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("changed\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "candidate")

    def test_ordinary_document_change_is_allowed(self):
        self.change("ordinary-notes.txt")
        self.assertEqual(0, self.gate().returncode)

    def test_protected_script_cannot_pass_with_label_only(self):
        self.change("scripts/strict_diagnostic_audit.py")
        self.assertNotEqual(0, self.gate(label=True).returncode)

    def test_protected_workflow_cannot_pass_with_reviewer_only(self):
        self.change(".github/workflows/protection.yml")
        self.assertNotEqual(0, self.gate(independent=True).returncode)

    def test_protected_change_requires_both_human_signals(self):
        self.change("src/PolicySharp.Analyzers/Example.cs")
        self.assertEqual(0, self.gate(label=True, independent=True).returncode)

    def test_codeowners_and_audit_tests_are_protected(self):
        self.change(".github/CODEOWNERS")
        self.assertNotEqual(0, self.gate().returncode)


if __name__ == "__main__":
    unittest.main()
