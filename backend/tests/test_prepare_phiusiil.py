"""Conversión PhiUSIIL sin red: etiquetas, categorías y no fuga de dominios."""

import csv
import tempfile
import unittest
from pathlib import Path

from app.ml.features import group_key
from ml_scripts.prepare_phiusiil import classify_category, prepare_external_csv


class PhiUSIILPreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.source = self.folder / "uci.csv"
        self.output = self.folder / "external.csv"

    def write_input(self, rows):
        with self.source.open("w", encoding="utf-8", newline="") as fp:
            writer = csv.DictWriter(fp, fieldnames=["FILENAME", "URL", "label", "URLLength"])
            writer.writeheader()
            for i, (url, label) in enumerate(rows):
                writer.writerow({"FILENAME": str(i), "URL": url,
                                 "label": label, "URLLength": len(url)})

    def read_output(self):
        with self.output.open("r", encoding="utf-8", newline="") as fp:
            return list(csv.DictReader(fp))

    def test_inverts_original_labels_and_keeps_private_urls_only_in_local_csv(self):
        self.write_input([
            ("https://libro-uno.example/account/login?token=PRIVADO", "1"),
            ("http://alarma-dos.example/verify", "0"),
        ])
        summary = prepare_external_csv(self.source, self.output, per_class=10)
        rows = self.read_output()
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["label"] for row in rows}, {"0", "1"})
        self.assertEqual(next(row["label"] for row in rows if "libro-uno" in row["url"]), "0")
        self.assertEqual(next(row["label"] for row in rows if "alarma-dos" in row["url"]), "1")
        self.assertEqual(summary["selected"]["total"], 2)
        self.assertNotIn("PRIVADO", str(summary))
        self.assertNotIn("libro-uno", str(summary))

    def test_excludes_entire_preexisting_domain_groups(self):
        rows = [
            ("https://ejemplo-uno.example/login", "1"),
            ("https://biblioteca-dos.example/", "1"),
            ("http://phishing-tres.example/login", "0"),
        ]
        self.write_input(rows)
        summary = prepare_external_csv(
            self.source, self.output, per_class=10,
            excluded_groups={group_key(rows[0][0])},
        )
        output = self.read_output()
        self.assertEqual(summary["skipped_overlap_with_previous_corpus"], 1)
        self.assertFalse(any("ejemplo-uno" in row["url"] for row in output))
        self.assertEqual(len(output), 2)

    def test_removes_domain_groups_with_conflicting_labels(self):
        self.write_input([
            ("https://same.example/login", "1"),
            ("http://www.same.example/verify", "0"),
            ("https://normal-dos.example/", "1"),
            ("http://phish-tres.example/", "0"),
        ])
        summary = prepare_external_csv(self.source, self.output, per_class=10)
        self.assertEqual(summary["conflicting_domain_groups"], 1)
        self.assertEqual(len(self.read_output()), 2)

    def test_category_rules(self):
        self.assertEqual(classify_category("https://uno.example/?next=%2Fhome"), "redirect")
        self.assertEqual(classify_category("https://dos.example/login"), "login")
        self.assertEqual(classify_category("https://tres.example/?q=texto"), "query")
        self.assertEqual(classify_category("https://cuatro.example/"), "other")

    def test_rejects_existing_output_and_same_file(self):
        self.write_input([
            ("https://uno.example/", "1"),
            ("http://dos.example/", "0"),
        ])
        with self.assertRaises(ValueError):
            prepare_external_csv(self.source, self.source, per_class=10)
        prepare_external_csv(self.source, self.output, per_class=10)
        with self.assertRaisesRegex(ValueError, "ya existe"):
            prepare_external_csv(self.source, self.output, per_class=10)

    def test_requires_original_columns(self):
        self.source.write_text("url,label\nhttps://uno.example/,1\n", encoding="utf-8")
        # Case-insensitive columns are deliberately supported.
        self.source.write_text("address,target\nhttps://uno.example/,1\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "columnas URL y label"):
            prepare_external_csv(self.source, self.output, per_class=10)


if __name__ == "__main__":
    unittest.main()
