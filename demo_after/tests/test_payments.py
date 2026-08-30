import unittest
from app.payments import process_payment

class TestPayments(unittest.TestCase):
    def test_process_payment(self):
        res = process_payment("u123", 100)
        self.assertEqual(res["status"], "paid")
