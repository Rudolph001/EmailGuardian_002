import csv
import sqlite3
import logging
from datetime import datetime
from io import StringIO
from tqdm import tqdm
from config import DATABASE_PATH, BATCH_SIZE, MAX_SPLITS, DELIMITERS
from models import get_db
from utils import (
    normalize_email, split_multi_value_field, parse_boolean, 
    extract_domain, is_internal_email, calculate_heuristic_score
)

def check_whitelist_during_import(cursor, event_data, recipients):
    """Check if an event should be whitelisted during import - requires ALL recipients to be whitelisted"""
    sender = event_data['sender']
    sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
    
    # Check if sender email is whitelisted
    cursor.execute("SELECT COUNT(*) FROM whitelist_emails WHERE email = ?", (sender.lower(),))
    if cursor.fetchone()[0] > 0:
        sender_whitelisted = True
    else:
        # Check if sender domain is whitelisted
        cursor.execute("SELECT COUNT(*) FROM whitelist_domains WHERE domain = ?", (sender_domain,))
        sender_whitelisted = cursor.fetchone()[0] > 0
    
    # For recipients, ALL must be whitelisted
    if recipients:
        for recipient in recipients:
            recipient_lower = recipient.lower()
            recipient_domain = recipient.split('@')[-1].lower() if '@' in recipient else ''
            
            # Check if recipient email is whitelisted
            cursor.execute("SELECT COUNT(*) FROM whitelist_emails WHERE email = ?", (recipient_lower,))
            if cursor.fetchone()[0] > 0:
                continue  # This recipient is whitelisted
            
            # Check if recipient domain is whitelisted
            cursor.execute("SELECT COUNT(*) FROM whitelist_domains WHERE domain = ?", (recipient_domain,))
            if cursor.fetchone()[0] > 0:
                continue  # This recipient is whitelisted
            
            # If we get here, this recipient is NOT whitelisted, so the event is not whitelisted
            return False
        
        # If we get here, all recipients are whitelisted
        return True
    
    # If no recipients, only sender matters
    return sender_whitelisted

def check_keywords_during_import(cursor, event_data, attachments):
    """Check for keyword matches during import and return matching keywords"""
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
                # Use regex matching
                pattern = re.compile(term, re.IGNORECASE)
                
                # Check subject
                if subject and pattern.search(subject):
                    matching_keywords.append(term)
                    continue
                
                # Check attachments
                if attachments_text and pattern.search(attachments_text):
                    matching_keywords.append(term)
                    
            else:
                # Simple case-insensitive string matching
                term_lower = term.lower()
                
                # Check subject
                if subject and term_lower in subject:
                    matching_keywords.append(term)
                    continue
                
                # Check attachments
                if attachments_text and term_lower in attachments_text:
                    matching_keywords.append(term)
                    
        except re.error:
            # Skip invalid regex patterns
            continue
    
    return list(set(matching_keywords))  # Remove duplicates

logger = logging.getLogger(__name__)

def normalize_row(row):
    """Normalize and validate a CSV row"""
    # Required fields
    _time = row.get('_time', '').strip()
    sender = normalize_email(row.get('sender', '').strip())
    subject = row.get('subject', '').strip()
    
    if not _time or not sender:
        raise ValueError("Missing required fields: _time or sender")
    
    # Multi-valued fields
    recipients_raw = row.get('recipients', '').strip()
    attachments_raw = row.get('attachments', '').strip()
    policies_raw = row.get('policy_name', '').strip()
    
    recipients = []
    if recipients_raw:
        raw_recipients = split_multi_value_field(recipients_raw, DELIMITERS)
        for email in raw_recipients[:MAX_SPLITS]:
            normalized = normalize_email(email)
            if normalized:
                recipients.append(normalized)
    
    attachments = []
    if attachments_raw:
        raw_attachments = split_multi_value_field(attachments_raw, DELIMITERS)
        attachments = [att.strip() for att in raw_attachments[:MAX_SPLITS] if att.strip()]
    
    policies = []
    if policies_raw:
        raw_policies = split_multi_value_field(policies_raw, DELIMITERS)
        policies = [pol.strip() for pol in raw_policies[:MAX_SPLITS] if pol.strip()]
    
    # Determine if internal to external
    sender_internal = is_internal_email(sender)
    has_external_recipient = any(not is_internal_email(email) for email in recipients)
    is_internal_to_external = sender_internal and has_external_recipient
    
    # Other fields
    event_data = {
        '_time': _time,
        'sender': sender,
        'subject': subject,
        'time_month': row.get('time_month', '').strip(),
        'leaver': 1 if parse_boolean(row.get('leaver', 0)) else 0,
        'termination_date': row.get('termination_date', '').strip(),
        'bunit': row.get('bunit', '').strip(),
        'department': row.get('department', '').strip(),
        'user_response': row.get('user_response', '').strip(),
        'final_outcome': row.get('final_outcome', '').strip(),
        'justifications': row.get('justifications', '').strip(),
        'is_internal_to_external': 1 if is_internal_to_external else 0
    }
    
    # Calculate heuristic ML score
    score_data = {
        'recipients': recipients,
        'attachments': attachments,
        'policies': policies,
        'leaver': event_data['leaver'],
        'termination_date': event_data['termination_date']
    }
    ml_score = calculate_heuristic_score(score_data)
    event_data['ml_score'] = ml_score
    event_data['ml_model_version'] = 'heuristic_v1'
    
    return event_data, recipients, attachments, policies

def insert_batch(conn, batch):
    """Insert a batch of normalized events"""
    cursor = conn.cursor()
    
    for event_data, recipients, attachments, policies in batch:
        # Check if event should be whitelisted
        is_whitelisted = check_whitelist_during_import(cursor, event_data, recipients)
        
        # Check for keyword matches
        matching_keywords = check_keywords_during_import(cursor, event_data, attachments)
        matching_keywords_str = ', '.join(matching_keywords) if matching_keywords else None
        
        # Insert main event
        cursor.execute("""
            INSERT INTO events (
                _time, sender, subject, time_month, leaver, termination_date,
                bunit, department, user_response, final_outcome, justifications,
                is_internal_to_external, ml_score, ml_model_version, is_whitelisted, matching_keywords
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_data['_time'], event_data['sender'], event_data['subject'],
            event_data['time_month'], event_data['leaver'], event_data['termination_date'],
            event_data['bunit'], event_data['department'], event_data['user_response'],
            event_data['final_outcome'], event_data['justifications'],
            event_data['is_internal_to_external'], event_data['ml_score'],
            event_data['ml_model_version'], 1 if is_whitelisted else 0, matching_keywords_str
        ))
        
        event_id = cursor.lastrowid
        
        # Insert recipients
        for email in recipients:
            cursor.execute("INSERT INTO recipients (event_id, email) VALUES (?, ?)", 
                         (event_id, email))
        
        # Insert attachments
        for filename in attachments:
            cursor.execute("INSERT INTO attachments (event_id, filename) VALUES (?, ?)", 
                         (event_id, filename))
        
        # Insert policies
        for policy in policies:
            cursor.execute("INSERT INTO policies (event_id, policy_name) VALUES (?, ?)", 
                         (event_id, policy))

def write_dead_letter(row_num, row, error, dead_letter_file="dead_letter.csv"):
    """Write failed row to dead letter file"""
    try:
        with open(dead_letter_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if f.tell() == 0:  # Write header if file is empty
                writer.writerow(['row_num', 'error', 'original_data'])
            writer.writerow([row_num, str(error), str(row)])
    except Exception as e:
        logger.error(f"Failed to write dead letter: {e}")

def ingest_csv(file_stream):
    """Main CSV ingestion function with streaming"""
    stats = {'inserted': 0, 'failed': 0, 'total': 0}
    
    try:
        # Read file content
        content = file_stream.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        
        # Create StringIO for csv.DictReader
        csv_file = StringIO(content)
        reader = csv.DictReader(csv_file)
        
        # Validate headers
        expected_headers = {
            '_time', 'sender', 'subject', 'attachments', 'recipients',
            'time_month', 'leaver', 'termination_date', 'bunit', 'department',
            'user_response', 'final_outcome', 'policy_name', 'justifications'
        }
        
        if not expected_headers.issubset(set(reader.fieldnames)):
            missing = expected_headers - set(reader.fieldnames)
            raise ValueError(f"Missing required CSV headers: {missing}")
        
        with get_db() as conn:
            batch = []
            
            # Count total rows for progress bar
            csv_file.seek(0)
            total_rows = sum(1 for _ in csv.DictReader(csv_file)) 
            csv_file.seek(0)
            reader = csv.DictReader(csv_file)  # Recreate reader
            
            with tqdm(total=total_rows, desc="Ingesting events") as pbar:
                for row_num, row in enumerate(reader, start=1):
                    stats['total'] += 1
                    
                    try:
                        normalized = normalize_row(row)
                        batch.append(normalized)
                        
                        if len(batch) >= BATCH_SIZE:
                            insert_batch(conn, batch)
                            stats['inserted'] += len(batch)
                            batch.clear()
                            conn.commit()
                        
                    except Exception as e:
                        logger.warning(f"Failed to process row {row_num}: {e}")
                        write_dead_letter(row_num, row, e)
                        stats['failed'] += 1
                    
                    pbar.update(1)
                
                # Insert remaining batch
                if batch:
                    insert_batch(conn, batch)
                    stats['inserted'] += len(batch)
                    conn.commit()
        
        logger.info(f"Ingestion complete: {stats}")
        return stats
        
    except Exception as e:
        logger.error(f"CSV ingestion failed: {e}")
        raise
