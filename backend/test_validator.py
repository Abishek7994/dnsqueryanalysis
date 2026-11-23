import unittest

from anomaly import AnomalyDetector
from validator import validate_dfa, validate_regex


class ValidatorTests(unittest.TestCase):
    def test_valid_domains_are_accepted_by_both_engines(self) -> None:
        for domain in ("example.com", "a.example.co", "a-b.123.example"):
            with self.subTest(domain=domain):
                self.assertTrue(validate_regex(domain)["is_valid"])
                self.assertTrue(validate_dfa(domain)["is_valid"])

    def test_invalid_domain_shapes_are_rejected_by_both_engines(self) -> None:
        for domain in (
            "",
            "singlelabel",
            "-bad.example.com",
            "bad-.example.com",
            "bad..example.com",
            "bad_label.example.com",
            "example.123",
        ):
            with self.subTest(domain=domain):
                self.assertFalse(validate_regex(domain)["is_valid"])
                self.assertFalse(validate_dfa(domain)["is_valid"])

    def test_dfa_traces_transitions_and_reports_first_rejected_character(self) -> None:
        result = validate_dfa("bad_.example.com")
        self.assertFalse(result["is_valid"])
        self.assertEqual(result["error_index"], 3)
        self.assertEqual(result["transitions"][-1]["to_state"], "REJECT")

    def test_domain_and_label_length_boundaries(self) -> None:
        max_domain = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        too_long_domain = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 62))
        too_long_label = f"{'a' * 64}.example.com"
        self.assertEqual(len(max_domain), 253)
        self.assertTrue(validate_regex(max_domain)["is_valid"])
        self.assertTrue(validate_dfa(max_domain)["is_valid"])
        for domain in (too_long_domain, too_long_label):
            with self.subTest(domain_length=len(domain)):
                self.assertFalse(validate_regex(domain)["is_valid"])
                self.assertFalse(validate_dfa(domain)["is_valid"])

    def test_entropy_and_client_rate_detection(self) -> None:
        detector = AnomalyDetector()
        self.assertGreater(detector.entropy("a8f3d9c2b7e1q5z6"), 3.8)
        result = None
        for timestamp in range(13):
            result = detector.analyze("www.example.com", "192.0.2.1", now=float(timestamp) / 10)
        self.assertEqual(result["status"], "CRITICAL")
        self.assertIn("rate spike", result["anomaly_reason"])


if __name__ == "__main__":
    unittest.main()
