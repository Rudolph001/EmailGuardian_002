import re
from email.utils import parseaddr
from config import INTERNAL_DOMAINS, DELIMITERS, MAX_SPLITS
import logging
from email_validator import validate_email, EmailNotValidError
import math


logger = logging.getLogger(__name__)

def normalize_email(email):
    """Normalize email address"""
    if not email:
        return ""

    try:
        name, addr = parseaddr(email)
        return addr.lower().strip()
    except:
        return email.lower().strip()

def split_multi_value_field(value, delimiters):
    """Split multi-value fields using various delimiters"""
    if not value:
        return []

    # Normalize delimiters
    for delimiter in delimiters[1:]:
        value = value.replace(delimiter, delimiters[0])

    parts = [part.strip() for part in value.split(delimiters[0])]
    return [part for part in parts if part]

def parse_boolean(value):
    """Parse boolean values from various formats"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'yes', 'on')
    return bool(value)

def extract_domain(email):
    """Extract domain from email address"""
    try:
        return email.split('@')[1].lower()
    except:
        return ""

def is_internal_email(email):
    """Check if email is from internal domain"""
    domain = extract_domain(email)
    return domain in INTERNAL_DOMAINS

def calculate_heuristic_score(event_data):
    """Calculate heuristic risk score for an event"""
    score = 0.0

    # Recipients factor (more recipients = higher risk)
    recipients = event_data.get('recipients', [])
    num_recipients = len(recipients)
    if num_recipients > 0:
        score += 0.8 * math.log1p(num_recipients)  # log1p for diminishing returns

    # Attachments factor
    attachments = event_data.get('attachments', [])
    if attachments:
        score += 0.6 * math.log1p(len(attachments))

    # External domains factor
    external_count = 0
    for email in recipients:
        if not is_internal_email(email):
            external_count += 1

    if external_count > 0:
        score += 1.2 * math.log1p(external_count)

    # Leaver factor (high risk)
    leaver = event_data.get('leaver', 0)
    if leaver or event_data.get('termination_date'):
        score += 1.5

    # Policy hits with configurable weights
    policies = event_data.get('policies', [])
    if policies:
        try:
            from models import get_ml_policy_weights
            policy_weights = get_ml_policy_weights()

            # Calculate weighted policy score
            policy_score = 0.0
            for policy in policies:
                weight = policy_weights.get(policy, 0.7)  # Default weight if not configured
                policy_score += weight

            score += policy_score
        except Exception:
            # Fallback to default scoring if ML policies table doesn't exist yet
            score += 0.7 * len(policies)

    # Normalize to [0, 1] using sigmoid
    return 1 / (1 + math.exp(-score + 2))