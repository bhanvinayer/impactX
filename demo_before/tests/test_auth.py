import unittest
from app.auth import validate_token, login, create_user

class TestAuth(unittest.TestCase):
    def test_validate_token(self):
        self.assertTrue(validate_token("valid_token"))

    def test_login(self):
        res = login("alice", "password")
        self.assertEqual(res["status"], "success")

    def test_create_user(self):
        u = create_user("alice", "alice@example.com")
        self.assertEqual(u["name"], "alice")
