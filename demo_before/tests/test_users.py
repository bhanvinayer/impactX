import unittest
from app.users import register_user

class TestUsers(unittest.TestCase):
    def test_register_user(self):
        res = register_user("bob", "bob@example.com", "secret")
        self.assertEqual(res["user"]["name"], "bob")
