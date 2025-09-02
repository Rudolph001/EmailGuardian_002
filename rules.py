import sqlite3
import logging
import fnmatch
import json
import re
from models import get_db

logger = logging.getLogger(__name__)

def check_exclusion_keywords_during_import(cursor, event_data, attachments):
    """Check for exclusion keyword matches during processing"""
    import re
    
    # Get all enabled exclusion keywords
    cursor.execute("""
        SELECT term, is_regex, check_subject, check_attachments 
        FROM exclusion_keywords 
        WHERE enabled = 1
    """)
    exclusion_keywords = cursor.fetchall()
    
    if not exclusion_keywords:
        return []
    
    matches = []
    subject = (event_data.get('subject') or '').lower()
    attachments_text = ' '.join(attachments).lower() if attachments else ''
    
    for keyword_row in exclusion_keywords:
        term = keyword_row[0]
        is_regex = keyword_row[1]
        check_subject = keyword_row[2]
        check_attachments = keyword_row[3]
        
        try:
            if is_regex:
                pattern = re.compile(term, re.IGNORECASE)
                if check_subject and subject and pattern.search(subject):
                    matches.append(term)
                    continue
                if check_attachments and attachments_text and pattern.search(attachments_text):
                    matches.append(term)
            else:
                term_lower = term.lower()
                if check_subject and subject and term_lower in subject:
                    matches.append(term)
                    continue
                if check_attachments and attachments_text and term_lower in attachments_text:
                    matches.append(term)
        except re.error:
            continue
    
    return list(set(matches))

def check_keywords_during_import(cursor, event_data, attachments):
    """Check for keyword matches during processing"""
    import re
    
    # Get all keywords
    cursor.execute("SELECT term, is_regex FROM keywords")
    keywords = cursor.fetchall()
    
    if not keywords:
        return []
    
    matching_keywords = []
    subject = (event_data.get('subject') or '').lower()
    attachments_text = ' '.join(attachments).lower() if attachments else ''
    
    for keyword_row in keywords:
        term = keyword_row[0]
        is_regex = keyword_row[1]
        
        try:
            if is_regex:
                pattern = re.compile(term, re.IGNORECASE)
                if subject and pattern.search(subject):
                    matching_keywords.append(term)
                    continue
                if attachments_text and pattern.search(attachments_text):
                    matching_keywords.append(term)
            else:
                term_lower = term.lower()
                if subject and term_lower in subject:
                    matching_keywords.append(term)
                    continue
                if attachments_text and term_lower in attachments_text:
                    matching_keywords.append(term)
        except re.error:
            continue
    
    return list(set(matching_keywords))

def get_rules(enabled_only=True):
    """Get all rules with condition summaries"""
    with get_db() as conn:
        cursor = conn.cursor()
        if enabled_only:
            cursor.execute("""
                SELECT id, name, action, conditions_json, priority, enabled
                FROM rules 
                WHERE enabled = 1
                ORDER BY priority ASC, id ASC
            """)
        else:
            cursor.execute("""
                SELECT id, name, action, conditions_json, priority, enabled
                FROM rules 
                ORDER BY priority ASC, id ASC
            """)

        rules = []
        for row in cursor.fetchall():
            rule = dict(row)
            rule['conditions_summary'] = _generate_condition_summary(rule['conditions_json'])
            rules.append(rule)

        return rules

def _generate_condition_summary(conditions_json):
    """Generate a human-readable summary of conditions"""
    if not conditions_json:
        return "No conditions"

    try:
        conditions = json.loads(conditions_json)
        if not conditions:
            return "No conditions"

        summaries = []
        for condition in conditions:
            field = condition.get('field', '')
            operator = condition.get('operator', '')
            value = condition.get('value', '')
            logic = condition.get('logic', 'AND')

            # Format field name
            field_map = {
                'sender': 'Sender',
                'sender_domain': 'Sender Domain',
                'subject': 'Subject',
                'recipients': 'Recipients',
                'recipient_domain': 'Recipient Domain',
                'bunit': 'Business Unit',
                'department': 'Department',
                'leaver': 'Is Leaver',
                'termination_date': 'Termination Date',
                'attachments': 'Attachments',
                'policies': 'Policies',
                'keywords': 'Matching Keywords',
                'ml_score': 'ML Score',
                'is_internal_to_external': 'Internal to External'
            }

            field_display = field_map.get(field, field)

            # Format operator
            operator_map = {
                'equals': '=',
                'contains': 'contains',
                'starts_with': 'starts with',
                'ends_with': 'ends with',
                'matches': 'matches',
                'greater_than': '>',
                'less_than': '<',
                'is_true': 'is true',
                'is_false': 'is false',
                'is_empty': 'is empty',
                'is_not_empty': 'is not empty'
            }

            operator_display = operator_map.get(operator, operator)

            # Check for negation
            negate = condition.get('negate', False)
            negate_prefix = "NOT " if negate else ""

            # Build condition string
            if operator in ['is_true', 'is_false', 'is_empty', 'is_not_empty']:
                condition_str = f"{negate_prefix}{field_display} {operator_display}"
            else:
                condition_str = f"{negate_prefix}{field_display} {operator_display} '{value}'"

            summaries.append(condition_str)

            # Add logic operator (except for last condition)
            if condition != conditions[-1]:
                summaries.append(f" {logic} ")

        return ''.join(summaries)

    except Exception as e:
        logger.warning(f"Error generating condition summary: {e}")
        return "Invalid conditions"

def add_rule(name, action, conditions, priority=100, enabled=True):
    """Add a new rule with JSON conditions"""
    with get_db() as conn:
        cursor = conn.cursor()
        conditions_json = json.dumps(conditions) if conditions else None
        cursor.execute("""
            INSERT INTO rules (name, action, conditions_json, priority, enabled)
            VALUES (?, ?, ?, ?, ?)
        """, (name, action, conditions_json, priority, 1 if enabled else 0))
        conn.commit()
        return cursor.lastrowid

def update_rule(rule_id, name=None, action=None, conditions=None, priority=None, enabled=None):
    """Update an existing rule"""
    with get_db() as conn:
        cursor = conn.cursor()

        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if action is not None:
            updates.append("action = ?")
            params.append(action)
        if conditions is not None:
            updates.append("conditions_json = ?")
            params.append(json.dumps(conditions) if conditions else None)
        if priority is not None:
            updates.append("priority = ?")
            params.append(priority)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)

        if updates:
            params.append(rule_id)
            cursor.execute(f"UPDATE rules SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
            return cursor.rowcount > 0

        return False

def delete_rule(rule_id):
    """Delete a rule"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        conn.commit()
        return cursor.rowcount > 0

# ============ EXCLUSION RULES CRUD FUNCTIONS ============

def get_exclusion_rules(enabled_only=True):
    """Get all exclusion rules with condition summaries"""
    with get_db() as conn:
        cursor = conn.cursor()
        if enabled_only:
            cursor.execute("""
                SELECT id, name, conditions_json, priority, enabled
                FROM exclusion_rules 
                WHERE enabled = 1
                ORDER BY priority ASC, id ASC
            """)
        else:
            cursor.execute("""
                SELECT id, name, conditions_json, priority, enabled
                FROM exclusion_rules 
                ORDER BY priority ASC, id ASC
            """)

        exclusion_rules = []
        for row in cursor.fetchall():
            rule = dict(row)
            rule['conditions_summary'] = _generate_condition_summary(rule['conditions_json'])
            exclusion_rules.append(rule)

        return exclusion_rules

def add_exclusion_rule(name, conditions, priority=100, enabled=True):
    """Add a new exclusion rule with JSON conditions"""
    with get_db() as conn:
        cursor = conn.cursor()
        conditions_json = json.dumps(conditions) if conditions else None
        cursor.execute("""
            INSERT INTO exclusion_rules (name, conditions_json, priority, enabled)
            VALUES (?, ?, ?, ?)
        """, (name, conditions_json, priority, 1 if enabled else 0))
        conn.commit()
        return cursor.lastrowid

def update_exclusion_rule(rule_id, name=None, conditions=None, priority=None, enabled=None):
    """Update an existing exclusion rule"""
    with get_db() as conn:
        cursor = conn.cursor()

        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if conditions is not None:
            updates.append("conditions_json = ?")
            params.append(json.dumps(conditions) if conditions else None)
        if priority is not None:
            updates.append("priority = ?")
            params.append(priority)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)

        if updates:
            params.append(rule_id)
            cursor.execute(f"UPDATE exclusion_rules SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
            return cursor.rowcount > 0

        return False

def delete_exclusion_rule(rule_id):
    """Delete an exclusion rule"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM exclusion_rules WHERE id = ?", (rule_id,))
        conn.commit()
        return cursor.rowcount > 0

def get_whitelist_domains():
    """Get all whitelisted domains"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, domain FROM whitelist_domains ORDER BY domain")
        return cursor.fetchall()

def get_whitelist_emails():
    """Get all whitelisted emails"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email FROM whitelist_emails ORDER BY email")
        return cursor.fetchall()

def add_whitelist_domain(domain):
    """Add domain to whitelist"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO whitelist_domains (domain) VALUES (?)", (domain,))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

def add_whitelist_email(email):
    """Add email to whitelist"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO whitelist_emails (email) VALUES (?)", (email,))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

def delete_whitelist_domain(domain_id):
    """Remove domain from whitelist"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM whitelist_domains WHERE id = ?", (domain_id,))
        conn.commit()
        return cursor.rowcount > 0

def delete_whitelist_email(email_id):
    """Remove email from whitelist"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM whitelist_emails WHERE id = ?", (email_id,))
        conn.commit()
        return cursor.rowcount > 0

def get_keywords():
    """Get all keywords"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, term, is_regex FROM keywords ORDER BY term")
        return cursor.fetchall()

def add_keyword(term, is_regex=False):
    """Add keyword"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO keywords (term, is_regex) VALUES (?, ?)", 
                         (term, 1 if is_regex else 0))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

def delete_keyword(keyword_id):
    """Delete keyword"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keywords WHERE id = ?", (keyword_id,))
        conn.commit()
        return cursor.rowcount > 0

def get_exclusion_keywords():
    """Get all exclusion keywords"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, term, is_regex, check_subject, check_attachments, enabled 
            FROM exclusion_keywords 
            ORDER BY term
        """)
        return cursor.fetchall()

def add_exclusion_keyword(term, is_regex=False, check_subject=True, check_attachments=True, enabled=True):
    """Add exclusion keyword"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO exclusion_keywords (term, is_regex, check_subject, check_attachments, enabled) 
                VALUES (?, ?, ?, ?, ?)
            """, (term, 1 if is_regex else 0, 1 if check_subject else 0, 
                  1 if check_attachments else 0, 1 if enabled else 0))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

def update_exclusion_keyword(keyword_id, term=None, is_regex=None, check_subject=None, 
                           check_attachments=None, enabled=None):
    """Update exclusion keyword"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        updates = []
        params = []
        
        if term is not None:
            updates.append("term = ?")
            params.append(term)
        if is_regex is not None:
            updates.append("is_regex = ?")
            params.append(1 if is_regex else 0)
        if check_subject is not None:
            updates.append("check_subject = ?")
            params.append(1 if check_subject else 0)
        if check_attachments is not None:
            updates.append("check_attachments = ?")
            params.append(1 if check_attachments else 0)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)
        
        if updates:
            params.append(keyword_id)
            cursor.execute(f"UPDATE exclusion_keywords SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
            return cursor.rowcount > 0
        
        return False

def delete_exclusion_keyword(keyword_id):
    """Delete exclusion keyword"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM exclusion_keywords WHERE id = ?", (keyword_id,))
        conn.commit()
        return cursor.rowcount > 0

def check_exclusion_keywords(event):
    """Check if event matches any exclusion keywords in subject and/or attachments"""
    import re
    
    # Get exclusion keywords
    exclusion_keywords = get_exclusion_keywords()
    
    # Filter to only enabled keywords
    exclusion_keywords = [kw for kw in exclusion_keywords if kw['enabled']]
    
    if not exclusion_keywords:
        return []
    
    matches = []
    
    # Check subject for exclusion keyword matches
    subject = (event['subject'] or '').lower()
    
    # Get attachments for checking
    attachments = []
    attachments_text = ''
    
    try:
        from models import get_event_detail
        event_detail = get_event_detail(event['id'])
        if event_detail and 'attachments' in event_detail:
            attachments = event_detail['attachments'] or []
            # attachments is already a list of strings (filenames), not dicts
            attachments_text = ' '.join(attachments).lower()
    except Exception:
        # If we can't get attachments, just continue with subject checking
        pass
    
    for keyword in exclusion_keywords:
        term = keyword['term']
        is_regex = keyword['is_regex']
        check_subject = keyword['check_subject']
        check_attachments = keyword['check_attachments']
        found_locations = []
        
        try:
            if is_regex:
                # Use regex matching
                pattern = re.compile(term, re.IGNORECASE)
                
                # Check subject if enabled
                if check_subject and pattern.search(subject):
                    found_locations.append('Subject')
                
                # Check attachments if enabled
                if check_attachments and attachments_text and pattern.search(attachments_text):
                    found_locations.append('Attachments')
            
            else:
                # Simple case-insensitive string matching
                
                # Check subject if enabled
                if check_subject and term.lower() in subject:
                    found_locations.append('Subject')
                
                # Check attachments if enabled
                if check_attachments and attachments_text and term.lower() in attachments_text:
                    found_locations.append('Attachments')
            
            # Add matches for each location found
            for location in found_locations:
                matches.append({
                    'term': term,
                    'is_regex': is_regex,
                    'location': location
                })
        
        except re.error:
            # Skip invalid regex patterns
            continue
    
    return matches

def check_whitelist_matches(event, recipients):
    """Check if event matches whitelist entries - requires ALL recipients to be whitelisted"""
    matches = []

    # Get whitelist data
    domains = get_whitelist_domains()
    emails = get_whitelist_emails()

    # Check sender domain
    sender_domain = event['sender'].split('@')[-1].lower() if '@' in event['sender'] else ''
    sender_whitelisted = False

    for domain in domains:
        if sender_domain == domain['domain'].lower():
            matches.append({
                'type': 'domain',
                'value': domain['domain'],
                'reason': f'Sender domain {sender_domain} is whitelisted'
            })
            sender_whitelisted = True
            break

    # Check sender email if domain not whitelisted
    if not sender_whitelisted:
        sender_email = event['sender'].lower()
        for email in emails:
            if sender_email == email['email'].lower():
                matches.append({
                    'type': 'email',
                    'value': email['email'],
                    'reason': f'Sender email {sender_email} is whitelisted'
                })
                sender_whitelisted = True
                break

    # For recipients, ALL must be whitelisted
    if recipients:
        all_recipients_whitelisted = True
        recipient_matches = []

        for recipient in recipients:
            recipient_lower = recipient.lower()
            recipient_domain = recipient.split('@')[-1].lower() if '@' in recipient else ''
            recipient_whitelisted = False

            # Check recipient domain
            for domain in domains:
                if recipient_domain == domain['domain'].lower():
                    recipient_matches.append({
                        'type': 'domain',
                        'value': domain['domain'],
                        'reason': f'Recipient domain {recipient_domain} is whitelisted'
                    })
                    recipient_whitelisted = True
                    break

            # Check recipient email if domain not whitelisted
            if not recipient_whitelisted:
                for email in emails:
                    if recipient_lower == email['email'].lower():
                        recipient_matches.append({
                            'type': 'email',
                            'value': email['email'],
                            'reason': f'Recipient email {recipient_lower} is whitelisted'
                        })
                        recipient_whitelisted = True
                        break

            # If this recipient is not whitelisted, the entire event fails
            if not recipient_whitelisted:
                all_recipients_whitelisted = False
                break

        # Only add recipient matches if ALL recipients are whitelisted
        if all_recipients_whitelisted:
            matches.extend(recipient_matches)
        else:
            # Clear all matches if not all recipients are whitelisted
            matches = []

    return matches


def check_keyword_matches(event):
    """Check if event matches any keywords in subject and attachments"""
    import re
    matches = []

    # First check if event should be excluded
    exclusion_matches = check_exclusion_keywords(event)
    if exclusion_matches:
        # Event matches exclusion keywords, so exclude it
        return []

    # Get keywords
    keywords = get_keywords()
    
    if not keywords:
        logger.debug("No keywords configured")
        return []

    # Handle both dict and sqlite3.Row objects
    event_id = event['id'] if hasattr(event, '__getitem__') else getattr(event, 'id', 'unknown')
    event_subject = event['subject'] if hasattr(event, '__getitem__') else getattr(event, 'subject', '')
    
    logger.debug(f"Checking {len(keywords)} keywords against event {event_id}")

    # Check subject for keyword matches
    subject = (event_subject or '').lower()
    logger.debug(f"Event subject: '{subject}'")

    # Get attachments for checking - try to get from event detail
    attachments = []
    attachments_text = ''

    try:
        from models import get_event_detail
        event_detail = get_event_detail(event_id)
        if event_detail and 'attachments' in event_detail:
            attachments = event_detail['attachments'] or []
            attachments_text = ' '.join(attachments).lower()
            logger.debug(f"Event attachments: {attachments}")
    except Exception as e:
        logger.debug(f"Could not get attachments for event {event.get('id')}: {e}")

    for keyword in keywords:
        term = keyword['term'].lower()
        is_regex = keyword['is_regex']
        found_locations = []
        
        logger.debug(f"Checking keyword '{term}' (regex: {is_regex})")

        try:
            if is_regex:
                # Use regex matching
                pattern = re.compile(term, re.IGNORECASE)

                # Check subject
                if subject and pattern.search(subject):
                    found_locations.append('Subject')
                    logger.debug(f"Regex keyword '{term}' matched in subject")

                # Check attachments
                if attachments_text and pattern.search(attachments_text):
                    found_locations.append('Attachments')
                    logger.debug(f"Regex keyword '{term}' matched in attachments")

            else:
                # Simple case-insensitive string matching

                # Check subject
                if subject and term in subject:
                    found_locations.append('Subject')
                    logger.debug(f"Literal keyword '{term}' matched in subject")

                # Check attachments
                if attachments_text and term in attachments_text:
                    found_locations.append('Attachments')
                    logger.debug(f"Literal keyword '{term}' matched in attachments")

            # Add matches for each location found
            for location in found_locations:
                matches.append({
                    'term': keyword['term'],  # Use original case
                    'type': 'regex' if is_regex else 'literal',
                    'location': location,
                    'match_type': 'Regex Pattern' if is_regex else 'Literal Text'
                })

        except re.error as e:
            logger.warning(f"Invalid regex pattern '{term}': {e}")
            continue

    logger.debug(f"Total keyword matches found: {len(matches)}")
    return matches

def _evaluate_condition(condition, event_data):
    """Evaluate a single condition against event data"""
    field = condition.get('field')
    operator = condition.get('operator')
    value = condition.get('value', '')
    negate = condition.get('negate', False)

    if not field or not operator:
        return False

    # Get field value from event data
    field_value = _get_field_value(field, event_data)

    # Handle different operators
    if operator == 'equals':
        return str(field_value).lower() == str(value).lower()
    elif operator == 'contains':
        return str(value).lower() in str(field_value).lower()
    elif operator == 'starts_with':
        return str(field_value).lower().startswith(str(value).lower())
    elif operator == 'ends_with':
        return str(field_value).lower().endswith(str(value).lower())
    elif operator == 'matches':
        return fnmatch.fnmatch(str(field_value).lower(), str(value).lower())
    elif operator == 'greater_than':
        try:
            return float(field_value) > float(value)
        except (ValueError, TypeError):
            return False
    elif operator == 'less_than':
        try:
            return float(field_value) < float(value)
        except (ValueError, TypeError):
            return False
    elif operator == 'is_true':
        return bool(field_value)
    elif operator == 'is_false':
        return not bool(field_value)
    elif operator == 'is_empty':
        return not field_value or field_value == ''
    elif operator == 'is_not_empty':
        result = field_value and field_value != ''
    else:
        result = False

    # Apply negation if specified
    if negate:
        result = not result

    return result

def _get_field_value(field, event_data):
    """Extract field value from event data"""
    event = event_data['event']
    recipients = event_data['recipients']
    attachments = event_data['attachments']
    policies = event_data['policies']

    # Ensure event is a dict for consistent access
    if hasattr(event, '_fields'):  # sqlite3.Row detection
        event = dict(event)

    if field == 'sender':
        return event['sender']
    elif field == 'sender_domain':
        return event['sender'].split('@')[1] if '@' in event['sender'] else ''
    elif field == 'subject':
        return event['subject'] or ''
    elif field == 'keywords':
        # For keyword field, return the stored matching_keywords
        matching_keywords = event.get('matching_keywords', '')
        logger.debug(f"Keywords field returning matching keywords: {matching_keywords}")
        return matching_keywords or ''
    elif field == 'recipients':
        return ', '.join(recipients)
    elif field == 'recipient_domain':
        domains = set()
        for email in recipients:
            if '@' in email:
                domains.add(email.split('@')[1])
        return ', '.join(domains)
    elif field == 'domain_risk_score':
        # Get domain risk score for this event
        try:
            from domain_ml import classify_event_domains, get_domain_risk_score
            domain_classifications = classify_event_domains(event['id'])
            return get_domain_risk_score(domain_classifications)
        except Exception:
            return 0.0
    elif field == 'sender_domain_classification':
        # Classify sender domain
        try:
            from domain_ml import domain_classifier
            from utils import extract_domain
            if not domain_classifier.model:
                domain_classifier.load_model()
            if domain_classifier.model:
                sender_domain = extract_domain(event['sender'])
                if sender_domain:
                    classification = domain_classifier.classify_domain(sender_domain)
                    result = classification.get('label', 'unknown')
                    logger.debug(f"Sender domain {sender_domain} classified as: {result}")
                    return result
            return 'unknown'
        except Exception as e:
            logger.debug(f"Error classifying sender domain: {e}")
            return 'unknown'
    elif field == 'recipient_domain_classifications':
        # Get all recipient domain classifications
        try:
            from domain_ml import domain_classifier
            from utils import extract_domain
            if not domain_classifier.model:
                domain_classifier.load_model()
            if domain_classifier.model:
                classifications = []
                for email in recipients:
                    domain = extract_domain(email)
                    if domain:
                        classification = domain_classifier.classify_domain(domain)
                        classifications.append(classification.get('label', 'unknown'))
                return ', '.join(classifications)
            return 'unknown'
        except Exception:
            return 'unknown'
    elif field == 'has_suspicious_domains':
        # Check if any domains are classified as suspicious
        try:
            from domain_ml import classify_event_domains
            domain_classifications = classify_event_domains(event['id'])
            for classification in domain_classifications:
                if classification.get('label') == 'suspicious':
                    return True
            return False
        except Exception:
            return False
    elif field == 'has_external_domains':
        # Check if any domains are not internal
        try:
            from domain_ml import classify_event_domains
            domain_classifications = classify_event_domains(event['id'])
            for classification in domain_classifications:
                if classification.get('label') != 'internal':
                    return True
            return False
        except Exception:
            return False
    elif field == 'bunit':
        return event['bunit'] or ''
    elif field == 'department':
        return event['department'] or ''
    elif field == 'leaver':
        # Convert to boolean: 1 = True, 0 = False
        return bool(event['leaver'] == 1)
    elif field == 'termination_date':
        return event['termination_date'] or ''
    elif field == 'attachments':
        return ', '.join(attachments)
    elif field == 'policies':
        return ', '.join(policies)
    elif field == 'ml_score':
        return event['ml_score'] or 0.0
    elif field == 'is_internal_to_external':
        return bool(event['is_internal_to_external'])

    return ''

def _evaluate_conditions(conditions, event_data):
    """Evaluate all conditions with AND/OR logic"""
    if not conditions:
        return False

    results = []
    operators = []

    logger.debug(f"Evaluating {len(conditions)} conditions for event {event_data['event']['id']}")

    for condition in conditions:
        result = _evaluate_condition(condition, event_data)
        results.append(result)
        operators.append(condition.get('logic', 'AND'))
        logger.debug(f"Condition {condition.get('field')} {condition.get('operator')} {condition.get('value')} = {result}")

    # Start with first result
    final_result = results[0]

    # Apply operators from left to right
    for i in range(1, len(results)):
        operator = operators[i-1]  # Previous condition's logic operator
        if operator == 'OR':
            final_result = final_result or results[i]
        else:  # AND
            final_result = final_result and results[i]

    logger.debug(f"Final result for event {event_data['event']['id']}: {final_result}")
    return final_result

def check_exclusion_rules(event, recipients, attachments, policies):
    """Check if event matches any exclusion rules"""
    exclusion_rules = get_exclusion_rules(enabled_only=True)
    
    if not exclusion_rules:
        return []
    
    logger.debug(f"Checking {len(exclusion_rules)} exclusion rules")
    
    # Prepare event data for condition evaluation
    event_data = {
        'event': event,
        'recipients': recipients,
        'attachments': attachments,
        'policies': policies
    }
    
    # Check each exclusion rule
    for rule in exclusion_rules:
        # Convert sqlite3.Row to dict for proper access
        rule_dict = dict(rule)
        if not rule_dict['conditions_json']:
            continue
            
        try:
            conditions = json.loads(rule_dict['conditions_json'])
            if _evaluate_conditions(conditions, event_data):
                logger.debug(f"Exclusion rule '{rule_dict['name']}' matched for event {event['id']}")
                return [{
                    'rule_id': rule_dict['id'],
                    'rule_name': rule_dict['name'],
                    'priority': rule_dict['priority']
                }]
        except Exception as e:
            logger.warning(f"Error evaluating exclusion rule {rule_dict['id']}: {e}")
            continue
    
    return []

def apply_rules_to_event(event_id):
    """Apply rules to a specific event and return matching actions"""
    from models import get_event_detail, update_event_status

    event_data = get_event_detail(event_id)
    if not event_data:
        return []

    event = event_data['event']
    recipients = event_data['recipients']
    attachments = event_data['attachments']
    policies = event_data['policies']
    actions = []
    trigger_reason = None

    # Convert sqlite3.Row objects to dicts for proper access
    if hasattr(event, '_fields'):  # sqlite3.Row detection
        event = dict(event)
    
    # Check exclusion rules first - if matched, exclude the event
    exclusion_rule_matches = check_exclusion_rules(event, recipients, attachments, policies)
    if exclusion_rule_matches:
        exclusion_rule = exclusion_rule_matches[0]  # Get first matching rule
        actions.append({
            'type': 'exclusion_rule',
            'action': 'exclude',
            'rule_name': exclusion_rule['rule_name'],
            'reason': f"Excluded by rule: {exclusion_rule['rule_name']}"
        })
        
        # Mark event as excluded
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE events SET trigger_reason = ? WHERE id = ?", 
                             (f"Excluded by rule: {exclusion_rule['rule_name']}", event_id))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to update exclusion rule reason for event {event_id}: {e}")
        
        return actions  # Return early - excluded events don't get processed further

    # Check exclusion keywords second - if matched, exclude the event
    exclusion_matches = check_exclusion_keywords(event)
    if exclusion_matches:
        exclusion_terms = [match['term'] for match in exclusion_matches[:3]]  # Show first 3
        if len(exclusion_matches) > 3:
            exclusion_terms.append(f"+ {len(exclusion_matches) - 3} more")
        
        actions.append({
            'type': 'exclusion',
            'action': 'exclude',
            'rule_name': 'Exclusion Keywords',
            'reason': f"Excluded by keywords: {', '.join(exclusion_terms)}"
        })
        
        # Mark event as excluded (you could add a new status or use existing mechanisms)
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE events SET trigger_reason = ? WHERE id = ?", 
                             (f"Excluded: {', '.join(exclusion_terms)}", event_id))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to update exclusion reason for event {event_id}: {e}")
        
        return actions  # Return early - excluded events don't get processed further

    # Check whitelist using new logic that requires ALL recipients to be whitelisted
    whitelist_matches = check_whitelist_matches(event, recipients)

    if whitelist_matches:
        # Determine the reason based on what was whitelisted
        sender_matches = [m for m in whitelist_matches if 'Sender' in m['reason']]
        recipient_matches = [m for m in whitelist_matches if 'Recipient' in m['reason']]

        if sender_matches and recipient_matches:
            reason = f"Sender and all recipients are whitelisted"
        elif sender_matches:
            reason = f"Sender is whitelisted and all recipients are whitelisted"
        else:
            reason = f"All recipients are whitelisted"

        actions.append({
            'type': 'whitelist',
            'action': 'allow',
            'rule_name': 'Whitelist (All Recipients Required)',
            'reason': reason
        })
        return actions

    # Apply rules
    rules = get_rules(enabled_only=True)

    for rule in rules:
        try:
            conditions_json = rule['conditions_json']
            if not conditions_json:
                continue

            conditions = json.loads(conditions_json)
            if not conditions:
                continue

            if _evaluate_conditions(conditions, event_data):
                trigger_reason = f"Rule: {rule['name']}"

                # Update the event with trigger reason
                try:
                    with get_db() as conn:
                        cursor = conn.cursor()
                        cursor.execute("UPDATE events SET trigger_reason = ? WHERE id = ?", (trigger_reason, event_id))
                        conn.commit()
                except Exception as e:
                    logger.warning(f"Failed to update trigger_reason for event {event_id}: {e}")

                actions.append({
                    'type': 'rule',
                    'action': rule['action'],
                    'rule_name': rule['name'],
                    'reason': f"Rule conditions matched: {rule['conditions_summary']}"
                })

                # Only return first matching rule (highest priority)
                break

        except Exception as e:
            logger.warning(f"Error evaluating rule {rule['id']}: {e}")
            continue

    return actions


def test_rule_against_events(conditions):
    """Test rule conditions against existing events"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get all events for testing
        cursor.execute("""
            SELECT e.*, 
                   GROUP_CONCAT(r.email) as recipients,
                   GROUP_CONCAT(a.filename) as attachments,
                   GROUP_CONCAT(p.policy_name) as policies
            FROM events e
            LEFT JOIN recipients r ON e.id = r.event_id
            LEFT JOIN attachments a ON e.id = a.event_id
            LEFT JOIN policies p ON e.id = p.event_id
            GROUP BY e.id
            ORDER BY e.id DESC
            LIMIT 100
        """)

        events = cursor.fetchall()
        total_events = len(events)

        if not conditions:
            return [], total_events

        matching_events = []

        for event_row in events:
            try:
                # Convert to dict for easier access
                event_dict = dict(event_row)

                # Parse multi-value fields safely
                recipients_str = event_dict.get('recipients') or ''
                attachments_str = event_dict.get('attachments') or ''
                policies_str = event_dict.get('policies') or ''
                
                event_dict['recipients'] = [r.strip() for r in recipients_str.split(',') if r.strip()] if recipients_str else []
                event_dict['attachments'] = [a.strip() for a in attachments_str.split(',') if a.strip()] if attachments_str else []
                event_dict['policies'] = [p.strip() for p in policies_str.split(',') if p.strip()] if policies_str else []

                # Test all conditions
                all_conditions_match = True

                for i, condition in enumerate(conditions):
                    field = condition.get('field', '')
                    operator = condition.get('operator', '')
                    value = condition.get('value', '')
                    logic = condition.get('logic', 'AND')

                    # Get negation flag
                    negate = condition.get('negate', False)
                    
                    condition_result = evaluate_condition(event_dict, field, operator, value)
                    
                    # Apply negation
                    if negate:
                        condition_result = not condition_result

                    if i == 0:
                        # First condition sets the result
                        all_conditions_match = condition_result
                    else:
                        # Apply logic operator with previous result
                        if logic == 'OR':
                            all_conditions_match = all_conditions_match or condition_result
                        else:  # AND
                            all_conditions_match = all_conditions_match and condition_result

                if all_conditions_match:
                    matching_events.append(event_dict)

            except Exception as e:
                logger.warning(f"Error evaluating event {event_dict.get('id', 'unknown')} against test conditions: {e}")
                continue

        return matching_events, total_events

def evaluate_condition(event, field, operator, value):
    """Evaluate a single condition against an event"""
    try:
        # Handle different field types
        if field == 'sender':
            event_value = event.get('sender', '')
        elif field == 'subject':
            event_value = event.get('subject', '') or ''
        elif field == 'keywords':
            # For testing, check if any keywords would match this event
            try:
                # Create a temporary event dict for keyword checking
                temp_event = {'id': event.get('id', 0), 'subject': event.get('subject', '')}
                keyword_matches = check_keyword_matches(temp_event)
                if keyword_matches:
                    event_value = ', '.join([match['term'] for match in keyword_matches])
                else:
                    event_value = ''
            except Exception:
                event_value = ''
        elif field == 'ml_score':
            event_value = float(event.get('ml_score', 0) or 0)
        elif field == 'domain_risk_score':
            # For testing, simulate domain risk score calculation
            try:
                from domain_ml import classify_event_domains, get_domain_risk_score
                domain_classifications = classify_event_domains(event.get('id', 0))
                event_value = get_domain_risk_score(domain_classifications)
            except Exception:
                event_value = 0.0
        elif field == 'sender_domain_classification':
            # For testing, simulate sender domain classification
            try:
                from domain_ml import domain_classifier
                from utils import extract_domain
                if not domain_classifier.model:
                    domain_classifier.load_model()
                if domain_classifier.model:
                    sender_domain = extract_domain(event.get('sender', ''))
                    if sender_domain:
                        classification = domain_classifier.classify_domain(sender_domain)
                        event_value = classification.get('label', 'unknown')
                    else:
                        event_value = 'unknown'
                else:
                    event_value = 'unknown'
            except Exception:
                event_value = 'unknown'
        elif field == 'recipient_domain_classifications':
            # For testing, simulate recipient domain classifications
            try:
                from domain_ml import domain_classifier
                from utils import extract_domain
                if not domain_classifier.model:
                    domain_classifier.load_model()
                if domain_classifier.model:
                    classifications = []
                    recipients = event.get('recipients', [])
                    for email in recipients:
                        domain = extract_domain(email)
                        if domain:
                            classification = domain_classifier.classify_domain(domain)
                            classifications.append(classification.get('label', 'unknown'))
                    event_value = ', '.join(classifications)
                else:
                    event_value = 'unknown'
            except Exception:
                event_value = 'unknown'
        elif field == 'has_suspicious_domains':
            # For testing, check if any domains are suspicious
            try:
                from domain_ml import classify_event_domains
                domain_classifications = classify_event_domains(event.get('id', 0))
                event_value = any(c.get('label') == 'suspicious' for c in domain_classifications)
            except Exception:
                event_value = False
        elif field == 'has_external_domains':
            # For testing, check if any domains are external
            try:
                from domain_ml import classify_event_domains
                domain_classifications = classify_event_domains(event.get('id', 0))
                event_value = any(c.get('label') != 'internal' for c in domain_classifications)
            except Exception:
                event_value = False
        elif field == 'recipient_count':
            event_value = len(event.get('recipients', []))
        elif field == 'attachment_count':
            event_value = len(event.get('attachments', []))
        elif field == 'policy_count':
            event_value = len(event.get('policies', []))
        elif field == 'is_internal_to_external':
            event_value = bool(event.get('is_internal_to_external', 0))
        elif field == 'leaver':  # Handle leaver field properly
            leaver_val = event.get('leaver', 0)
            # Convert to boolean: 1 = True, 0 = False, handle None
            if leaver_val is None:
                event_value = False
            else:
                event_value = bool(int(leaver_val) == 1)
        elif field == 'bunit':
            event_value = event.get('bunit', '') or ''
        elif field == 'department':
            event_value = event.get('department', '') or ''
        elif field == 'termination_date':
            event_value = event.get('termination_date', '') or ''
        else:
            # Default to getting the field directly
            event_value = event.get(field, '')

        # Apply operator
        result = False
        if operator == 'equals':
            result = str(event_value).lower() == str(value).lower()
        elif operator == 'contains':
            result = str(value).lower() in str(event_value).lower()
        elif operator == 'starts_with':
            return str(event_value).lower().startswith(str(value).lower())
        elif operator == 'ends_with':
            return str(event_value).lower().endswith(str(value).lower())
        elif operator == 'greater_than':
            try:
                return float(event_value) > float(value)
            except (ValueError, TypeError):
                return False
        elif operator == 'less_than':
            try:
                return float(event_value) < float(value)
            except (ValueError, TypeError):
                return False
        elif operator == 'is_true':
            # For boolean fields, check if the value is True
            return bool(event_value) is True
        elif operator == 'is_false':
            # For boolean fields, check if the value is False
            return bool(event_value) is False
        elif operator == 'is_empty':
            return not event_value or str(event_value).strip() == ''
        elif operator == 'is_not_empty':
            result = event_value and str(event_value).strip() != ''
        else:
            result = False

        # Apply negation if specified (for testing, we need to get negate from somewhere)
        # For now, we'll assume testing doesn't use negation or we'd need to pass it
        return result

    except Exception as e:
        logger.error(f"Error evaluating condition {field} {operator} {value} against event value {event_value}: {e}")
        return False


def process_all_events_for_rules():
    """Process all events to apply rules and set trigger reasons - optimized"""
    logger.info("Starting to process all events for rule triggers...")

    # Use the optimized version
    return process_all_events_for_rules_with_progress()

def process_all_events_for_rules_comprehensive():
    """Process all events for rules, keywords, exclusions, and whitelist changes"""
    logger.info("Starting comprehensive processing of all events for management changes...")
    
    # Get all enabled rules, exclusions, keywords, and whitelist data
    rules = get_rules(enabled_only=True)
    exclusion_rules = get_exclusion_rules(enabled_only=True)
    keywords = get_keywords()
    exclusion_keywords = get_exclusion_keywords()
    whitelist_domains = get_whitelist_domains()
    whitelist_emails = get_whitelist_emails()

    with get_db() as conn:
        cursor = conn.cursor()

        # Get all events for reprocessing
        cursor.execute("""
            SELECT e.id, e.sender, e.subject, e.bunit, e.department, e.leaver, 
                   e.termination_date, e.ml_score, e.is_internal_to_external,
                   GROUP_CONCAT(DISTINCT r.email) as recipients,
                   GROUP_CONCAT(DISTINCT a.filename) as attachments,
                   GROUP_CONCAT(DISTINCT p.policy_name) as policies
            FROM events e
            LEFT JOIN recipients r ON e.id = r.event_id
            LEFT JOIN attachments a ON e.id = a.event_id
            LEFT JOIN policies p ON e.id = p.event_id
            GROUP BY e.id
            ORDER BY e.id
        """)

        events_data = cursor.fetchall()

    total_events = len(events_data)
    triggered_count = 0
    batch_size = 100
    updates = []

    for event_row in events_data:
        try:
            event = dict(event_row)
            event_id = event['id']
            
            # Parse multi-value fields
            recipients = [r.strip() for r in (event['recipients'] or '').split(',') if r.strip()]
            attachments = [a.strip() for a in (event['attachments'] or '').split(',') if a.strip()]
            policies = [p.strip() for p in (event['policies'] or '').split(',') if p.strip()]

            trigger_reason = None
            matching_keywords = []
            is_whitelisted = False

            # Check whitelist first
            is_whitelisted = _fast_whitelist_check(event, recipients, whitelist_domains, whitelist_emails)

            # Check exclusion keywords
            exclusion_matches = check_exclusion_keywords_during_import(cursor, event, attachments)
            if exclusion_matches:
                exclusion_terms = exclusion_matches[:3]
                if len(exclusion_matches) > 3:
                    exclusion_terms.append(f"+ {len(exclusion_matches) - 3} more")
                trigger_reason = f"Excluded: {', '.join(exclusion_terms)}"
                triggered_count += 1

            # Check regular keywords if not excluded
            elif not exclusion_matches:
                matching_keywords = check_keywords_during_import(cursor, event, attachments)

            # Check exclusion rules if not already excluded
            if not trigger_reason:
                event_data = {
                    'event': event,
                    'recipients': recipients,
                    'attachments': attachments,
                    'policies': policies
                }

                for exclusion_rule in exclusion_rules:
                    try:
                        conditions_json = exclusion_rule['conditions_json']
                        if not conditions_json:
                            continue

                        conditions = json.loads(conditions_json)
                        if not conditions:
                            continue

                        if _evaluate_conditions(conditions, event_data):
                            trigger_reason = f"Excluded by rule: {exclusion_rule['name']}"
                            triggered_count += 1
                            break

                    except Exception as e:
                        logger.warning(f"Error evaluating exclusion rule {exclusion_rule['id']} for event {event_id}: {e}")
                        continue

                # Check regular rules if not excluded
                if not trigger_reason:
                    for rule in rules:
                        try:
                            conditions_json = rule['conditions_json']
                            if not conditions_json:
                                continue

                            conditions = json.loads(conditions_json)
                            if not conditions:
                                continue

                            if _evaluate_conditions(conditions, event_data):
                                trigger_reason = f"Rule: {rule['name']}"
                                triggered_count += 1
                                break

                        except Exception as e:
                            logger.warning(f"Error evaluating rule {rule['id']} for event {event_id}: {e}")
                            continue

            # Prepare updates
            matching_keywords_str = ', '.join(matching_keywords) if matching_keywords else None
            updates.append((
                1 if is_whitelisted else 0,
                matching_keywords_str,
                trigger_reason,
                event_id
            ))

            # Process batches
            if len(updates) >= batch_size:
                cursor.executemany("""
                    UPDATE events 
                    SET is_whitelisted = ?, matching_keywords = ?, trigger_reason = ? 
                    WHERE id = ?
                """, updates)
                conn.commit()
                updates = []

        except Exception as e:
            logger.error(f"Error processing event {event.get('id', 'unknown')}: {e}")
            continue

    # Process remaining updates
    if updates:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                UPDATE events 
                SET is_whitelisted = ?, matching_keywords = ?, trigger_reason = ? 
                WHERE id = ?
            """, updates)
            conn.commit()

    logger.info(f"Completed comprehensive processing of {total_events} events. {triggered_count} events had management rules triggered.")
    return total_events, triggered_count

def process_all_events_for_rules_with_progress():
    """Process all events to apply rules and set trigger reasons with progress tracking - optimized"""
    from flask import current_app
    
    logger.info("Starting to process all events for rule triggers with progress tracking...")

    # Get all enabled rules first to avoid repeated queries
    rules = get_rules(enabled_only=True)
    exclusion_rules = get_exclusion_rules(enabled_only=True)
    
    # Get keywords once
    keywords = get_keywords()
    
    # Get whitelist data once
    whitelist_domains = get_whitelist_domains()
    whitelist_emails = get_whitelist_emails()
    
    # Get exclusion keywords once
    exclusion_keywords = get_exclusion_keywords()

    with get_db() as conn:
        cursor = conn.cursor()

        # Get events with all related data in one query for better performance
        cursor.execute("""
            SELECT e.id, e.sender, e.subject, e.bunit, e.department, e.leaver, 
                   e.termination_date, e.ml_score, e.is_internal_to_external,
                   GROUP_CONCAT(DISTINCT r.email) as recipients,
                   GROUP_CONCAT(DISTINCT a.filename) as attachments,
                   GROUP_CONCAT(DISTINCT p.policy_name) as policies
            FROM events e
            LEFT JOIN recipients r ON e.id = r.event_id
            LEFT JOIN attachments a ON e.id = a.event_id
            LEFT JOIN policies p ON e.id = p.event_id
            WHERE (e.trigger_reason IS NULL OR e.trigger_reason = '') 
            AND e.status != 'closed' 
            AND e.is_whitelisted = 0 
            AND e.follow_up = 0
            GROUP BY e.id
            ORDER BY e.id
        """)

        events_data = cursor.fetchall()

    total_events = len(events_data)
    processed_count = 0
    triggered_count = 0
    batch_size = 100
    updates = []

    # Update total events count in progress tracking
    try:
        current_app.config['rule_processing']['total_events'] = total_events
    except:
        pass

    for event_row in events_data:
        try:
            event = dict(event_row)
            event_id = event['id']
            
            # Parse multi-value fields
            recipients = [r.strip() for r in (event['recipients'] or '').split(',') if r.strip()]
            attachments = [a.strip() for a in (event['attachments'] or '').split(',') if a.strip()]
            policies = [p.strip() for p in (event['policies'] or '').split(',') if p.strip()]

            trigger_reason = None
            rule_triggered = False

            # Fast whitelist check using preloaded data - but still process for trigger reasons
            is_whitelisted = _fast_whitelist_check(event, recipients, whitelist_domains, whitelist_emails)
            
            # Note: Whitelisted events still get processed for trigger reasons, 
            # they just don't appear in the main dashboard categories

            # Check exclusion keywords first
            exclusion_matches = check_exclusion_keywords(event)
            if exclusion_matches:
                exclusion_terms = [match['term'] for match in exclusion_matches[:3]]  # Show first 3
                if len(exclusion_matches) > 3:
                    exclusion_terms.append(f"+ {len(exclusion_matches) - 3} more")
                trigger_reason = f"Excluded: {', '.join(exclusion_terms)}"
                rule_triggered = True

            # Check exclusion rules if not already excluded by keywords
            if not rule_triggered:
                event_data = {
                    'event': event,
                    'recipients': recipients,
                    'attachments': attachments,
                    'policies': policies
                }

                # Check exclusion rules first
                for exclusion_rule in exclusion_rules:
                    try:
                        conditions_json = exclusion_rule['conditions_json']
                        if not conditions_json:
                            continue

                        conditions = json.loads(conditions_json)
                        if not conditions:
                            continue

                        if _evaluate_conditions(conditions, event_data):
                            trigger_reason = f"Excluded by rule: {exclusion_rule['name']}"
                            rule_triggered = True
                            break

                    except Exception as e:
                        logger.warning(f"Error evaluating exclusion rule {exclusion_rule['id']} for event {event_id}: {e}")
                        continue

                # Check regular rules if not excluded
                if not rule_triggered:
                    for rule in rules:
                        try:
                            conditions_json = rule['conditions_json']
                            if not conditions_json:
                                continue

                            conditions = json.loads(conditions_json)
                            if not conditions:
                                continue

                            if _evaluate_conditions(conditions, event_data):
                                trigger_reason = f"Rule: {rule['name']}"
                                rule_triggered = True
                                break

                        except Exception as e:
                            logger.warning(f"Error evaluating rule {rule['id']} for event {event_id}: {e}")
                            continue

            # Batch the database updates
            if trigger_reason:
                updates.append((trigger_reason, event_id))
                triggered_count += 1

            processed_count += 1

            # Process batches for better performance
            if len(updates) >= batch_size:
                _execute_batch_updates(updates)
                updates = []

            # Update progress tracking
            try:
                current_app.config['rule_processing'].update({
                    'processed_count': processed_count,
                    'triggered_count': triggered_count
                })
            except:
                pass

            if processed_count % 500 == 0:  # Log less frequently
                logger.info(f"Processed {processed_count} events, {triggered_count} triggered so far...")

        except Exception as e:
            logger.error(f"Error processing event {event.get('id', 'unknown')}: {e}")
            processed_count += 1
            continue

    # Process remaining updates
    if updates:
        _execute_batch_updates(updates)

    logger.info(f"Completed processing {processed_count} events. {triggered_count} events had rules triggered.")
    return processed_count, triggered_count

def _fast_whitelist_check(event, recipients, whitelist_domains, whitelist_emails):
    """Fast whitelist check using preloaded data"""
    try:
        # Check sender domain
        sender_domain = event['sender'].split('@')[-1].lower() if '@' in event['sender'] else ''
        sender_whitelisted = False

        for domain in whitelist_domains:
            if sender_domain == domain['domain'].lower():
                sender_whitelisted = True
                break

        if not sender_whitelisted:
            sender_email = event['sender'].lower()
            for email in whitelist_emails:
                if sender_email == email['email'].lower():
                    sender_whitelisted = True
                    break

        # For recipients, ALL must be whitelisted
        if recipients:
            all_recipients_whitelisted = True
            for recipient in recipients:
                recipient_lower = recipient.lower()
                recipient_domain = recipient.split('@')[-1].lower() if '@' in recipient else ''
                recipient_whitelisted = False

                # Check recipient domain
                for domain in whitelist_domains:
                    if recipient_domain == domain['domain'].lower():
                        recipient_whitelisted = True
                        break

                # Check recipient email if domain not whitelisted
                if not recipient_whitelisted:
                    for email in whitelist_emails:
                        if recipient_lower == email['email'].lower():
                            recipient_whitelisted = True
                            break

                if not recipient_whitelisted:
                    all_recipients_whitelisted = False
                    break

            return all_recipients_whitelisted
        
        return sender_whitelisted

    except Exception:
        return False

def _fast_keyword_check(event, keywords):
    """Fast keyword check using preloaded keywords"""
    try:
        subject = (event['subject'] or '').lower()
        
        for keyword in keywords:
            term = keyword['term']
            is_regex = keyword['is_regex']

            try:
                if is_regex:
                    pattern = re.compile(term, re.IGNORECASE)
                    if pattern.search(subject):
                        return True
                else:
                    if term.lower() in subject:
                        return True
            except re.error:
                continue

        return False
    except Exception:
        return False

def _execute_batch_updates(updates):
    """Execute batch database updates for better performance"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.executemany("UPDATE events SET trigger_reason = ? WHERE id = ?", updates)
            conn.commit()
    except Exception as e:
        logger.error(f"Error executing batch updates: {e}")