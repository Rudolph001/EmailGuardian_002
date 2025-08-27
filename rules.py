import sqlite3
import logging
import fnmatch
import json
import re
from models import get_db

logger = logging.getLogger(__name__)

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

            # Build condition string
            if operator in ['is_true', 'is_false', 'is_empty', 'is_not_empty']:
                condition_str = f"{field_display} {operator_display}"
            else:
                condition_str = f"{field_display} {operator_display} '{value}'"

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

    # Get keywords
    keywords = get_keywords()

    # Check subject for keyword matches
    subject = (event['subject'] or '').lower()

    # Get attachments for checking - try to get from event detail
    attachments = []
    attachments_text = ''

    try:
        from models import get_event_detail
        event_detail = get_event_detail(event['id'])
        if event_detail and 'attachments' in event_detail:
            attachments = event_detail['attachments'] or []
            attachments_text = ' '.join(attachments).lower()
    except Exception:
        # If we can't get attachments, just continue with subject checking
        pass

    for keyword in keywords:
        term = keyword['term']
        is_regex = keyword['is_regex']
        found_locations = []

        try:
            if is_regex:
                # Use regex matching
                pattern = re.compile(term, re.IGNORECASE)

                # Check subject
                if pattern.search(subject):
                    found_locations.append('Subject')

                # Check attachments
                if attachments_text and pattern.search(attachments_text):
                    found_locations.append('Attachments')

            else:
                # Simple case-insensitive string matching

                # Check subject
                if term.lower() in subject:
                    found_locations.append('Subject')

                # Check attachments
                if attachments_text and term.lower() in attachments_text:
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

def _evaluate_condition(condition, event_data):
    """Evaluate a single condition against event data"""
    field = condition.get('field')
    operator = condition.get('operator')
    value = condition.get('value', '')

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
        return field_value and field_value != ''

    return False

def _get_field_value(field, event_data):
    """Extract field value from event data"""
    event = event_data['event']
    recipients = event_data['recipients']
    attachments = event_data['attachments']
    policies = event_data['policies']

    if field == 'sender':
        return event['sender']
    elif field == 'sender_domain':
        return event['sender'].split('@')[1] if '@' in event['sender'] else ''
    elif field == 'subject':
        return event['subject'] or ''
    elif field == 'keywords':
        # Check if any keywords match this event
        keyword_matches = check_keyword_matches(event)
        if keyword_matches:
            # Return the matched keywords as a comma-separated string
            return ', '.join([match['term'] for match in keyword_matches])
        return ''
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

def apply_rules_to_event(event_id):
    """Apply rules to a specific event and return matching actions"""
    from models import get_event_detail, update_event_status

    event_data = get_event_detail(event_id)
    if not event_data:
        return []

    event = event_data['event']
    recipients = event_data['recipients']
    actions = []
    trigger_reason = None

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

    # Check keyword matches first
    keyword_matches = check_keyword_matches(event)
    if keyword_matches:
        keyword_terms = [match['term'] for match in keyword_matches[:3]]  # Show first 3
        if len(keyword_matches) > 3:
            keyword_terms.append(f"+ {len(keyword_matches) - 3} more")
        trigger_reason = f"Keywords: {', '.join(keyword_terms)}"

        # Update the event with trigger reason
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE events SET trigger_reason = ? WHERE id = ?", (trigger_reason, event_id))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to update trigger_reason for event {event_id}: {e}")

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

                    condition_result = evaluate_condition(event_dict, field, operator, value)

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
        if operator == 'equals':
            return str(event_value).lower() == str(value).lower()
        elif operator == 'contains':
            return str(value).lower() in str(event_value).lower()
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
            return event_value and str(event_value).strip() != ''
        else:
            return False

    except Exception as e:
        logger.error(f"Error evaluating condition {field} {operator} {value} against event value {event_value}: {e}")
        return False


def process_all_events_for_rules():
    """Process all events to apply rules and set trigger reasons"""
    logger.info("Starting to process all events for rule triggers...")

    with get_db() as conn:
        cursor = conn.cursor()

        # Get all events that don't have a trigger_reason set
        cursor.execute("""
            SELECT id FROM events 
            WHERE (trigger_reason IS NULL OR trigger_reason = '') 
            AND status != 'closed' 
            AND is_whitelisted = 0 
            AND follow_up = 0
        """)

        event_ids = [row[0] for row in cursor.fetchall()]

    processed_count = 0
    triggered_count = 0

    for event_id in event_ids:
        try:
            # Apply rules to this event (this will also update trigger_reason if applicable)
            actions = apply_rules_to_event(event_id)

            # Check if any rules or keywords were triggered
            rule_actions = [action for action in actions if action.get('type') == 'rule']
            if rule_actions:
                triggered_count += 1

            processed_count += 1

            if processed_count % 100 == 0:
                logger.info(f"Processed {processed_count} events, {triggered_count} triggered so far...")

        except Exception as e:
            logger.error(f"Error processing event {event_id} for rules: {e}")
            continue

    logger.info(f"Completed processing {processed_count} events. {triggered_count} events had rules triggered.")
    return processed_count, triggered_count

def process_all_events_for_rules_with_progress():
    """Process all events to apply rules and set trigger reasons with progress tracking"""
    from flask import current_app
    
    logger.info("Starting to process all events for rule triggers with progress tracking...")

    with get_db() as conn:
        cursor = conn.cursor()

        # Get all events that don't have a trigger_reason set
        cursor.execute("""
            SELECT id FROM events 
            WHERE (trigger_reason IS NULL OR trigger_reason = '') 
            AND status != 'closed' 
            AND is_whitelisted = 0 
            AND follow_up = 0
        """)

        event_ids = [row[0] for row in cursor.fetchall()]

    total_events = len(event_ids)
    processed_count = 0
    triggered_count = 0

    # Update total events count in progress tracking
    try:
        current_app.config['rule_processing']['total_events'] = total_events
    except:
        pass

    for event_id in event_ids:
        try:
            # Apply rules to this event (this will also update trigger_reason if applicable)
            actions = apply_rules_to_event(event_id)

            # Check if any rules or keywords were triggered
            rule_actions = [action for action in actions if action.get('type') == 'rule']
            if rule_actions:
                triggered_count += 1

            processed_count += 1

            # Update progress tracking
            try:
                current_app.config['rule_processing'].update({
                    'processed_count': processed_count,
                    'triggered_count': triggered_count
                })
            except:
                pass

            if processed_count % 100 == 0:
                logger.info(f"Processed {processed_count} events, {triggered_count} triggered so far...")

        except Exception as e:
            logger.error(f"Error processing event {event_id} for rules: {e}")
            continue

    logger.info(f"Completed processing {processed_count} events. {triggered_count} events had rules triggered.")
    return processed_count, triggered_count