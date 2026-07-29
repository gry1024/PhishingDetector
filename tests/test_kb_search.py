import unittest

from src.database import init_db, search_kb


class KnowledgeBaseSearchTest(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_should_match_ip_port_and_urgency_patterns(self):
        query = "请立即验证账户 http://192.168.1.100:8080/verify 否则账户冻结"
        hits = search_kb(query, limit=5)

        self.assertGreaterEqual(len(hits), 1)
        titles = [item["title"] for item in hits]
        self.assertTrue(any("IP直连" in title for title in titles))


if __name__ == "__main__":
    unittest.main()
