"""Payments module."""
import json
from app.config import TIMEOUT

def process_payment(user_id, amount):
    """Process payment transaction."""
    if amount <= 0:
        return {"status": "failed", "reason": "invalid_amount"}
    return {"status": "paid", "amount": amount, "timeout": TIMEOUT}

def refund_payment(transaction_id):
    """Refund existing payment."""
    return {"status": "refunded", "tx": transaction_id}
