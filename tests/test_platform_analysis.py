"""
tests/test_platform_analysis.py
================================
Unit & Integration tests for Multi-Platform Detection, Adapters, Evidence Engine, and POST /api/profile/analyze.
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from platforms.detector import PlatformDetector
from platforms.schema import NormalizedProfile, PlatformEvidence
from platforms.evidence import EvidenceEngine
from platforms.instagram import InstagramAdapter
from platforms.x import XAdapter
from platforms.tiktok import TikTokAdapter
from platforms.facebook import FacebookAdapter
from platforms.youtube import YouTubeAdapter
import app as flask_app


class TestPlatformDetector(unittest.TestCase):
    def test_instagram_url_detection(self):
        res = PlatformDetector.detect("https://instagram.com/cristiano")
        self.assertEqual(res["platform"], "instagram")
        self.assertEqual(res["identifier"], "cristiano")
        self.assertEqual(res["inputType"], "url")

    def test_x_url_detection(self):
        res = PlatformDetector.detect("https://x.com/elonmusk")
        self.assertEqual(res["platform"], "x")
        self.assertEqual(res["identifier"], "elonmusk")

        res2 = PlatformDetector.detect("https://twitter.com/jack")
        self.assertEqual(res2["platform"], "x")
        self.assertEqual(res2["identifier"], "jack")

    def test_tiktok_url_detection(self):
        res = PlatformDetector.detect("https://www.tiktok.com/@khaby.lame")
        self.assertEqual(res["platform"], "tiktok")
        self.assertEqual(res["identifier"], "khaby.lame")

    def test_facebook_url_detection(self):
        res = PlatformDetector.detect("https://facebook.com/zuck")
        self.assertEqual(res["platform"], "facebook")
        self.assertEqual(res["identifier"], "zuck")

    def test_youtube_url_detection(self):
        res = PlatformDetector.detect("https://youtube.com/@mkbhd")
        self.assertEqual(res["platform"], "youtube")
        self.assertEqual(res["identifier"], "mkbhd")

    def test_username_handle_detection(self):
        res = PlatformDetector.detect("@sample_user")
        self.assertEqual(res["identifier"], "sample_user")

    def test_invalid_input_raises_value_error(self):
        with self.assertRaises(ValueError):
            PlatformDetector.detect("invalid link with spaces !!!")


class TestEvidenceEngine(unittest.TestCase):
    def test_evidence_generation(self):
        prof = NormalizedProfile(
            platform="instagram",
            platform_user_id="ig_12345",
            username="test_user",
            followers=10000,
            following=50,
            posts_count=120,
            verified=True,
            avatar_url="https://example.com/pic.jpg",
            bio="Security researcher",
        )
        evidence = EvidenceEngine.process(prof)
        self.assertTrue(len(evidence) >= 3)
        types = [e.type for e in evidence]
        self.assertIn("API_VERIFIED_IDENTITY", types)
        self.assertIn("OFFICIAL_VERIFICATION_STATUS", types)
        self.assertIn("FOLLOWER_FOLLOWING_RATIO", types)


class TestAPIAnalyzeEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = flask_app.app.test_client()

    def test_analyze_endpoint_success(self):
        res = self.client.post("/api/profile/analyze", json={"input": "https://instagram.com/test_user"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("profile", data)
        self.assertIn("evidence", data)
        self.assertIn("analysis", data)
        self.assertIn("metadata", data)
        self.assertEqual(data["metadata"]["platform"], "instagram")

    def test_analyze_endpoint_missing_input(self):
        res = self.client.post("/api/profile/analyze", json={"input": ""})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "INVALID_INPUT")

    def test_analyze_endpoint_invalid_platform(self):
        res = self.client.post("/api/profile/analyze", json={"input": "invalid link format !!!"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "UNSUPPORTED_PLATFORM")


if __name__ == "__main__":
    unittest.main()
