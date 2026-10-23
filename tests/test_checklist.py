"""Checklist cites only the catalogued public identifiers."""

import json
import unittest

from spacelab.checklist import ITEMS, REFERENCES, SEGMENTS, render, select_items


class ChecklistTests(unittest.TestCase):
    def test_every_citation_is_in_the_catalog_and_used(self):
        cited = set()
        for item in ITEMS:
            self.assertTrue(item.check_id.startswith("SL-"))
            self.assertTrue(item.summary)
            self.assertTrue(item.practices)
            for segment in item.segments:
                self.assertIn(segment, SEGMENTS)
            for reference_id in item.reference_ids:
                self.assertIn(reference_id, REFERENCES)
                reference = REFERENCES[reference_id]
                self.assertTrue(reference.identifier)
                self.assertTrue(reference.title)
                self.assertTrue(reference.url.startswith("https://"))
                cited.add(reference_id)
        self.assertEqual(cited, set(REFERENCES))

    def test_known_framework_ids_are_present_and_invented_ones_are_not(self):
        blob = render("text") + render("json")
        for token in ("CM0031", "CM0030", "CM0038", "SC-8", "SC-12", "8270", "8401", "355.0-B-2"):
            self.assertIn(token, blob)
        for invented in ("CM9999", "SPARTA-99", "NIST-SAT-1", "CSF-SPACE-9"):
            self.assertNotIn(invented, blob)

    def test_formats_and_segment_filter(self):
        as_json = json.loads(render("json", "space"))
        self.assertTrue(as_json["items"])
        for item in as_json["items"]:
            self.assertIn("space", item["segments"])
        markdown = render("md")
        self.assertIn("# SpaceLab hardening checklist", markdown)
        self.assertIn("SL-01", render("text"))
        self.assertGreater(len(select_items("ground")), 0)
        with self.assertRaises(ValueError):
            select_items("orbit")


if __name__ == "__main__":
    unittest.main()
