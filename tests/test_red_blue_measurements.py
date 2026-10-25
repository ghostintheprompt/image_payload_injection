"""Controls for marker measurement, pixel uncertainty, and failure reporting."""
import io
import logging
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from PIL import Image, ImageDraw, PngImagePlugin
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ipi.sanitizer import RedBlueTester

MARKER = "AUDIT_MARKER_TEXT_ONLY"

def png(text=False, metadata=False):
    image = Image.new("RGB", (400, 100), "white")
    if text:
        ImageDraw.Draw(image).text((10, 30), MARKER, fill="black")
    info = PngImagePlugin.PngInfo()
    if metadata:
        info.add_text("audit", MARKER)
    output = io.BytesIO()
    image.save(output, format="PNG", pnginfo=info)
    return output.getvalue()

class MeasurementControls(unittest.TestCase):
    def setUp(self):
        self.tester = RedBlueTester.__new__(RedBlueTester)
        self.tester.logger = logging.getLogger("measurement-test")

    def test_clean_image_is_not_an_adversarial_success(self):
        result = self.tester._check_survival(png(), MARKER, "adversarial_perturbation")
        self.assertIsNone(result["survived"])
        self.assertEqual(result["status"], "unknown")

    def test_rendered_text_is_unknown_not_removed(self):
        image = png(text=True)
        for technique in ["invisible_contrast", "micro_typography", "channel_isolated"]:
            with self.subTest(technique=technique):
                result = self.tester._check_survival(image, MARKER, technique)
                self.assertIsNone(result["survived"])
        self.assertTrue(self.tester._compare_pixels(image, image)["pixels_identical"])
        self.assertFalse(self.tester._compare_pixels(image, png())["pixels_identical"])

    def test_metadata_positive_control_and_full_marker(self):
        self.assertTrue(self.tester._check_survival(png(metadata=True), MARKER, "png_text_chunk")["survived"])
        prefix_only = MARKER[:20].encode()
        result = self.tester._check_survival(prefix_only, MARKER, "png_text_chunk")
        self.assertFalse(result["survived"])
        self.assertEqual(result["status"], "marker_not_found")

    def test_empty_marker_rejected(self):
        with self.assertRaises(ValueError):
            self.tester._check_survival(png(), "", "png_text_chunk")
        with self.assertRaises(ValueError):
            self.tester.run_full_matrix(png(), " ")

    def test_failed_imagemagick_is_not_original_input(self):
        with patch("ipi.sanitizer.subprocess.run", return_value=SimpleNamespace(returncode=1, stderr=b"fixture failure")):
            with self.assertRaisesRegex(RuntimeError, "ImageMagick failed"):
                self.tester._run_imagemagick(png(), "convert {input} -strip {output}")

    def test_missing_imagemagick_output_is_error(self):
        with patch("ipi.sanitizer.subprocess.run", return_value=SimpleNamespace(returncode=0, stderr=b"")):
            with self.assertRaisesRegex(RuntimeError, "no output"):
                self.tester._run_imagemagick(png(), "convert {input} -strip {output}")

    def test_invalid_image_propagates_pillow_error(self):
        with self.assertRaises(Exception):
            self.tester._run_pillow_reopen(b"not an image")

    def test_matrix_keeps_unknown_and_errors_and_no_automatic_severity(self):
        # Control the generators; this test measures orchestration, not attacks.
        base, generated = png(), png(text=True, metadata=True)
        names = ["_make_exif_usercomment_payload", "_make_png_text_payload", "_make_polyglot_payload", "_make_invisible_text_payload", "_make_micro_typography_payload", "_make_channel_isolated_payload", "_make_adversarial_perturbation"]
        from contextlib import ExitStack
        with ExitStack() as stack:
            for name in names:
                stack.enter_context(patch.object(self.tester, name, return_value=generated))
            stack.enter_context(patch.object(self.tester, "_sanitize", return_value=generated))
            matrix = self.tester.run_full_matrix(base, MARKER)
            self.assertEqual(len(matrix["findings"]), 28)
            self.assertEqual(len(matrix["retained_markers"]), 12)
            self.assertEqual(sum(r["status"] == "unknown" for r in matrix["findings"]), 16)
            self.assertTrue(all(r["pixels_identical"] for r in matrix["findings"] if r["status"] == "unknown"))
            self.assertEqual(matrix["critical_bypasses"], [])
            self.assertFalse(matrix["model_tested"])
            rendered = self.tester.report_text(matrix)
            self.assertIn("UNKNOWN", rendered)
            self.assertNotIn("BYPASS", rendered)
            with patch.object(self.tester, "_sanitize", side_effect=RuntimeError("pipeline fixture failure")):
                errors = self.tester.run_full_matrix(base, MARKER)
                self.assertTrue(all(r["status"] == "error" and r["pipeline_success"] is False for r in errors["findings"]))
                self.assertIn("ERROR", self.tester.report_text(errors))

    def test_generator_noop_is_not_a_success(self):
        base = png()
        with patch.object(self.tester, "_make_exif_usercomment_payload", return_value=base):
            matrix = self.tester.run_full_matrix(base, MARKER)
        rows = matrix["summary"]["exif_usercomment"].values()
        self.assertTrue(all(r["status"] == "error" and "Generation failed" in r["note"] for r in rows))

if __name__ == "__main__":
    unittest.main()
