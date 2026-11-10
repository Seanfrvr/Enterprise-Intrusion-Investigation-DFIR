import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "pipeline" / "analyze.py"
OUTPUT = ROOT / "output"

class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(SCRIPT)], check=True, capture_output=True, text=True)

    def test_inventory_is_fixture_scoped(self):
        data = json.loads((OUTPUT / "inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(data["total_fixture_events"], 83)
        self.assertEqual(len(data["by_fixture"]), 6)
        self.assertEqual(sum(data["by_fixture"].values()), 83)

    def test_source_families_present(self):
        data = json.loads((OUTPUT / "inventory.json").read_text(encoding="utf-8"))
        expected = {
            "aws:cloudtrail", "_json", "stream:dns",
            "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "ms:aad:signin", "ms:o365:management"
        }
        self.assertTrue(expected.issubset(set(data["by_sourcetype"])))

    def test_timeline_is_utc_sorted(self):
        data = json.loads((OUTPUT / "timeline.json").read_text(encoding="utf-8"))
        times = [row["timestamp_utc"] for row in data["events"]]
        self.assertEqual(times, sorted(times))
        self.assertEqual(data["timezone"], "UTC")

    def test_integrity_hashes_are_sha256(self):
        data = json.loads((OUTPUT / "fixture-integrity.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["files"]), 6)
        for item in data["files"]:
            self.assertEqual(len(item["sha256"]), 64)
            self.assertGreater(item["bytes"], 0)

if __name__ == "__main__":
    unittest.main()
