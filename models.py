import sqlite3
import logging
from contextlib import contextmanager
from config import DATABASE_PATH

logger = logging.getLogger(__name__)

# Database schema
DDL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    _time TEXT NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT,
    time_month TEXT,
    leaver INTEGER DEFAULT 0,
    termination_date TEXT,
    bunit TEXT,
    department TEXT,
    user_response TEXT,
    final_outcome TEXT,
    justifications TEXT,
    is_internal_to_external INTEGER DEFAULT 0,
    ml_score REAL,
    ml_model_version TEXT,
    status TEXT DEFAULT 'open',
    is_whitelisted INTEGER DEFAULT 0,
    follow_up INTEGER DEFAULT 0,
    follow_up_date TEXT,
    closed_date TEXT,
    closed_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    policy_name TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL,
    conditions_json TEXT,
    priority INTEGER DEFAULT 100,
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whitelist_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whitelist_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    term TEXT NOT NULL UNIQUE,
    is_regex INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ml_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_name TEXT NOT NULL UNIQUE,
    risk_weight REAL DEFAULT 1.0,
    category TEXT DEFAULT 'other',
    description TEXT,
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS closure_reasons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reason TEXT NOT NULL UNIQUE,
    requires_reference INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ml_scoring_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL UNIQUE,
    condition_field TEXT NOT NULL,
    condition_operator TEXT NOT NULL,
    condition_value TEXT,
    score_adjustment REAL NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(_time);
CREATE INDEX IF NOT EXISTS idx_events_sender ON events(sender);
CREATE INDEX IF NOT EXISTS idx_events_ml_score ON events(ml_score);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_is_whitelisted ON events(is_whitelisted);
CREATE INDEX IF NOT EXISTS idx_events_follow_up ON events(follow_up);
CREATE INDEX IF NOT EXISTS idx_recipients_email ON recipients(email);
CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority);
"""

def get_db_connection():
    """Get database connection with optimized settings"""
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA cache_size=-20000;")
    return conn

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize database with schema"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            for stmt in DDL.split(";\n"):
                if stmt.strip():
                    cursor.execute(stmt)

            # Check if conditions_json column exists and add if missing
            cursor.execute("PRAGMA table_info(rules)")
            columns = [row[1] for row in cursor.fetchall()]

            if 'conditions_json' not in columns:
                logger.info("Adding missing conditions_json column to rules table")
                cursor.execute("ALTER TABLE rules ADD COLUMN conditions_json TEXT")

            # Add is_whitelisted column if it doesn't exist (migration)
            try:
                cursor.execute("ALTER TABLE events ADD COLUMN is_whitelisted INTEGER DEFAULT 0")
                conn.commit()
                logger.info("Added is_whitelisted column to events table")
            except sqlite3.OperationalError:
                # Column already exists
                pass

            # Add columns that might not exist in older versions
            for column_def in [
                "ALTER TABLE events ADD COLUMN leaver INTEGER DEFAULT 0",
                "ALTER TABLE events ADD COLUMN termination_date TEXT",
                "ALTER TABLE events ADD COLUMN email_sent INTEGER DEFAULT 0",
                "ALTER TABLE events ADD COLUMN email_sent_date TEXT",
                "ALTER TABLE events ADD COLUMN closure_reason TEXT",
                "ALTER TABLE events ADD COLUMN closure_notes TEXT",
                "ALTER TABLE events ADD COLUMN closure_reference TEXT",
                "ALTER TABLE events ADD COLUMN trigger_reason TEXT"
            ]:
                try:
                    cursor.execute(column_def)
                except sqlite3.OperationalError:
                    pass  # Column already exists

            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_sender ON events(sender)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(_time)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ml_score ON events(ml_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_is_whitelisted ON events(is_whitelisted)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_follow_up ON events(follow_up)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_recipients_email ON recipients(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(policy_name)")
            
            # Additional performance indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_composite ON events(is_whitelisted, status, follow_up, ml_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_high_risk ON events(ml_score, is_whitelisted, status, follow_up)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_recipients_event_id ON recipients(event_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attachments_event_id ON attachments(event_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_policies_event_id ON policies(event_id)")

            conn.commit()
            
            # Initialize default closure reasons if none exist
            cursor.execute("SELECT COUNT(*) FROM closure_reasons")
            if cursor.fetchone()[0] == 0:
                default_reasons = [
                    ('BAU', 0),
                    ('Personal', 0),
                    ('Escalation', 1)  # Requires reference
                ]
                cursor.executemany(
                    "INSERT INTO closure_reasons (reason, requires_reference) VALUES (?, ?)",
                    default_reasons
                )
                conn.commit()
                logger.info("Initialized default closure reasons")

            # Initialize default ML scoring rules if none exist
            cursor.execute("SELECT COUNT(*) FROM ml_scoring_rules")
            if cursor.fetchone()[0] == 0:
                default_scoring_rules = [
                    ('Base Risk Score', 'ml_score', 'exists', '', 0.2),
                    ('Multiple Recipients', 'recipient_count', '>', '5', 0.15),
                    ('Has Attachments', 'attachment_count', '>', '0', 0.1),
                    ('External Recipients', 'external_recipients', '>', '0', 0.2),
                    ('Leaver Flag', 'leaver', '=', '1', 0.3),
                    ('Internal to External', 'is_internal_to_external', '=', '1', 0.25),
                    ('Policy Violations', 'policy_count', '>', '2', 0.2),
                    ('Subject Length Risk', 'subject_length', '>', '100', 0.05),
                    ('Urgent Subject', 'subject', 'contains', 'urgent', 0.1),
                    ('Confidential Subject', 'subject', 'contains', 'confidential', 0.15)
                ]
                cursor.executemany(
                    "INSERT INTO ml_scoring_rules (rule_name, condition_field, condition_operator, condition_value, score_adjustment) VALUES (?, ?, ?, ?, ?)",
                    default_scoring_rules
                )
                conn.commit()
                logger.info("Initialized default ML scoring rules")
        
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def get_event_count():
    """Get total number of events"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        return cursor.fetchone()[0]

def get_dashboard_stats():
    """Get dashboard statistics for all events"""
    with get_db() as conn:
        cursor = conn.cursor()

        # High risk events (ML score > 0.7)
        cursor.execute("SELECT COUNT(*) FROM events WHERE ml_score > 0.7")
        high_risk_count = cursor.fetchone()[0]

        # Low risk events (ML score <= 0.3)
        cursor.execute("SELECT COUNT(*) FROM events WHERE ml_score <= 0.3 AND ml_score IS NOT NULL")
        low_risk_count = cursor.fetchone()[0]

        # Whitelisted events
        cursor.execute("SELECT COUNT(*) FROM events WHERE is_whitelisted = 1")
        whitelisted_count = cursor.fetchone()[0]

        # Closed events
        cursor.execute("SELECT COUNT(*) FROM events WHERE status = 'closed'")
        closed_count = cursor.fetchone()[0]

        # Follow-up events
        cursor.execute("SELECT COUNT(*) FROM events WHERE follow_up = 1")
        follow_up_count = cursor.fetchone()[0]

        # Rule triggered events - calculate using actual logic
        rule_triggered_count = _get_rule_triggered_count()

        # High risk events - exclude those that would be in rule triggered
        actual_high_risk_count = _get_actual_high_risk_count()

        return {
            'high_risk_count': actual_high_risk_count,
            'low_risk_count': low_risk_count,
            'whitelisted_count': whitelisted_count,
            'closed_count': closed_count,
            'follow_up_count': follow_up_count,
            'rule_triggered_count': rule_triggered_count
        }

def _get_rule_triggered_count():
    """Get count of events that would appear in Rule Triggered filter"""
    from rules import check_keyword_matches, apply_rules_to_event

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM events
            WHERE is_whitelisted = 0 
            AND status != 'closed'
            AND follow_up = 0
            ORDER BY datetime(_time) DESC
            LIMIT 200
        """)
        events = cursor.fetchall()

    triggered_count = 0
    for event in events:
        try:
            # Check if event has keyword matches
            event_data = get_event_detail(event['id'])
            if event_data:
                keyword_matches = check_keyword_matches(event_data['event'])
                if keyword_matches:
                    triggered_count += 1
                    continue

                # Check regular rules
                actions = apply_rules_to_event(event['id'])
                rule_actions = [action for action in actions if action.get('type') == 'rule']
                if rule_actions:
                    triggered_count += 1
        except Exception:
            continue

    return triggered_count

def _get_actual_high_risk_count():
    """Get count of events that would appear in High Risk filter"""
    from rules import check_keyword_matches, apply_rules_to_event

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM events
            WHERE ml_score > 0.7 
            AND is_whitelisted = 0 
            AND status != 'closed'
            AND follow_up = 0
            ORDER BY ml_score DESC, datetime(_time) DESC
            LIMIT 200
        """)
        events = cursor.fetchall()

    high_risk_count = 0
    for event in events:
        try:
            # Check if event has keyword matches - if so, it should be in rule triggered instead
            event_data = get_event_detail(event['id'])
            if event_data:
                keyword_matches = check_keyword_matches(event_data['event'])
                if keyword_matches:
                    continue  # Skip - would be in rule triggered

                # Check regular rules
                actions = apply_rules_to_event(event['id'])
                rule_actions = [action for action in actions if action.get('type') == 'rule']
                if not rule_actions:  # No rules triggered - keep in high risk
                    high_risk_count += 1
        except Exception:
            # If there's an error, include the event in high-risk
            high_risk_count += 1

    return high_risk_count

def get_recent_events(limit=10):
    """Get recent events"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up
            FROM events
            ORDER BY datetime(_time) DESC
            LIMIT ?
        """, (limit,))
        return cursor.fetchall()

def search_events(query, limit=100, offset=0):
    """Search events by sender or subject"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up, trigger_reason,
                   closure_reason, closure_notes, closure_reference,
                   email_sent, email_sent_date
            FROM events
            WHERE sender LIKE ? OR subject LIKE ?
            ORDER BY datetime(_time) DESC
            LIMIT ? OFFSET ?
        """, (f"%{query}%", f"%{query}%", limit, offset))
        return cursor.fetchall()

def get_event_detail(event_id):
    """Get detailed event information"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get main event
        cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
        event = cursor.fetchone()

        if not event:
            return None

        # Get recipients
        cursor.execute("SELECT email FROM recipients WHERE event_id = ?", (event_id,))
        recipients = [row[0] for row in cursor.fetchall()]

        # Get attachments
        cursor.execute("SELECT filename FROM attachments WHERE event_id = ?", (event_id,))
        attachments = [row[0] for row in cursor.fetchall()]

        # Get policies
        cursor.execute("SELECT policy_name FROM policies WHERE event_id = ?", (event_id,))
        policies = [row[0] for row in cursor.fetchall()]

        return {
            'event': event,
            'recipients': recipients,
            'attachments': attachments,
            'policies': policies
        }

def get_whitelisted_events(limit=100, offset=0):
    """Get events that have been whitelisted"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up, trigger_reason,
                   closure_reason, closure_notes, closure_reference,
                   email_sent, email_sent_date
            FROM events
            WHERE is_whitelisted = 1
            ORDER BY datetime(_time) DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return cursor.fetchall()

def get_whitelisted_events_count():
    """Get count of whitelisted events"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events WHERE is_whitelisted = 1")
        return cursor.fetchone()[0]

def get_follow_up_events(limit=100, offset=0):
    """Get events marked for follow-up"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up, follow_up_date, email_sent, email_sent_date,
                   trigger_reason, closure_reason, closure_notes, closure_reference
            FROM events
            WHERE follow_up = 1 AND status != 'closed'
            ORDER BY datetime(follow_up_date) ASC, datetime(_time) DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return cursor.fetchall()

def get_follow_up_events_count():
    """Get count of follow-up events"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events WHERE follow_up = 1 AND status != 'closed'")
        return cursor.fetchone()[0]

def get_closed_events(limit=100, offset=0):
    """Get closed events"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, closed_date, closed_by, closure_reason, closure_notes, closure_reference,
                   is_whitelisted, follow_up, trigger_reason, email_sent, email_sent_date
            FROM events
            WHERE status = 'closed'
            ORDER BY datetime(closed_date) DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return cursor.fetchall()

def get_closed_events_count():
    """Get count of closed events"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events WHERE status = 'closed'")
        return cursor.fetchone()[0]

def get_high_risk_events(limit=100):
    """Get events with high ML scores (>0.7) that haven't been processed by rules, are not whitelisted, and don't have keyword matches"""
    from rules import get_rules, apply_rules_to_event, check_keyword_matches

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up
            FROM events
            WHERE ml_score > 0.7 
            AND is_whitelisted = 0 
            AND status != 'closed'
            AND follow_up = 0
            ORDER BY ml_score DESC, datetime(_time) DESC
            LIMIT ?
        """, (limit * 2,))  # Get more events to filter through
        all_high_risk = cursor.fetchall()

    # Get enabled rules to check against
    rules = get_rules(enabled_only=True)

    high_risk_not_rule_triggered = []

    # Check each high-risk event to see if it would be caught by rules or keywords
    for event in all_high_risk:
        try:
            # Check if event has keyword matches - if so, it should be in rule triggered instead
            keyword_matches = check_keyword_matches(event)
            if keyword_matches:
                continue  # Skip this event - it should appear in rule triggered

            # Check regular rules
            actions = apply_rules_to_event(event['id'])
            # If no rule-based actions were triggered, include in high-risk
            rule_actions = [action for action in actions if action.get('type') == 'rule']
            if not rule_actions:  # No rules triggered - keep in high risk
                high_risk_not_rule_triggered.append(event)

            # Stop when we have enough results
            if len(high_risk_not_rule_triggered) >= limit:
                break

        except Exception:
            # If there's an error checking rules/keywords, include the event in high-risk
            high_risk_not_rule_triggered.append(event)
            if len(high_risk_not_rule_triggered) >= limit:
                break

    return high_risk_not_rule_triggered

def get_rule_triggered_events(limit=100):
    """Get events that have actually triggered configured rules, keyword matches, or are not whitelisted"""
    from rules import get_rules, apply_rules_to_event, check_keyword_matches

    # Get recent events to check against rules (excluding whitelisted, closed, and follow-up)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up
            FROM events
            WHERE is_whitelisted = 0 
            AND status != 'closed'
            AND follow_up = 0
            ORDER BY datetime(_time) DESC
            LIMIT ?
        """, (limit * 2,))  # Get more events to filter through
        all_events = cursor.fetchall()

    triggered_events = []

    # Check each event against rules and keywords
    for event in all_events:
        try:
            # Convert to dict so we can add trigger_reason
            event_dict = dict(event)

            # Check if event has keyword matches
            keyword_matches = check_keyword_matches(event)
            if keyword_matches:
                # Build keyword reason string
                keyword_terms = [match['term'] for match in keyword_matches[:3]]  # Show first 3
                if len(keyword_matches) > 3:
                    keyword_terms.append(f"+ {len(keyword_matches) - 3} more")
                event_dict['trigger_reason'] = f"Keywords: {', '.join(keyword_terms)}"
                triggered_events.append(event_dict)
                # Stop when we have enough results
                if len(triggered_events) >= limit:
                    break
                continue

            # Check regular rules
            actions = apply_rules_to_event(event['id'])
            # If any rule-based actions (not whitelist) were triggered, include this event
            rule_actions = [action for action in actions if action.get('type') == 'rule']
            if rule_actions:
                # Use the first rule action's name as the reason
                event_dict['trigger_reason'] = f"Rule: {rule_actions[0]['rule_name']}"
                triggered_events.append(event_dict)

            # Stop when we have enough results
            if len(triggered_events) >= limit:
                break

        except Exception:
            # Skip events that cause errors during rule application
            continue

    return triggered_events

def get_remaining_events(limit=100):
    """Get events that are not in Rule Triggered or High Risk categories"""
    from rules import check_keyword_matches, apply_rules_to_event

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up
            FROM events
            WHERE is_whitelisted = 0 
            AND status != 'closed'
            AND follow_up = 0
            ORDER BY datetime(_time) DESC
            LIMIT ?
        """, (limit * 3,))  # Get more events to filter through
        all_events = cursor.fetchall()

    remaining_events = []

    # Check each event to exclude those that would appear in Rule Triggered or High Risk
    for event in all_events:
        try:
            # Skip if this would be in High Risk (ML score > 0.7)
            if event['ml_score'] and event['ml_score'] > 0.7:
                # Check if it would be caught by rules/keywords
                keyword_matches = check_keyword_matches(event)
                if keyword_matches:
                    continue  # Skip - would be in Rule Triggered

                actions = apply_rules_to_event(event['id'])
                rule_actions = [action for action in actions if action.get('type') == 'rule']
                if rule_actions:
                    continue  # Skip - would be in Rule Triggered
                else:
                    continue  # Skip - would be in High Risk

            # Skip if this would be in Rule Triggered
            keyword_matches = check_keyword_matches(event)
            if keyword_matches:
                continue  # Skip - would be in Rule Triggered

            actions = apply_rules_to_event(event['id'])
            rule_actions = [action for action in actions if action.get('type') == 'rule']
            if rule_actions:
                continue  # Skip - would be in Rule Triggered

            # This event doesn't belong in High Risk or Rule Triggered, so include it
            remaining_events.append(event)

            # Stop when we have enough results
            if len(remaining_events) >= limit:
                break

        except Exception:
            # If there's an error checking, include the event to be safe
            remaining_events.append(event)
            if len(remaining_events) >= limit:
                break

    return remaining_events

def update_event_status(event_id, status=None, is_whitelisted=None, follow_up=None, 
                        follow_up_date=None, closed_date=None, closed_by=None, 
                        email_sent=None, email_sent_date=None, closure_reason=None,
                        closure_notes=None, closure_reference=None):
    """Update event status and related fields"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Build dynamic update query
        updates = []
        params = []

        if status is not None:
            updates.append("status = ?")
            params.append(status)

        if is_whitelisted is not None:
            updates.append("is_whitelisted = ?")
            params.append(1 if is_whitelisted else 0)

        if follow_up is not None:
            updates.append("follow_up = ?")
            params.append(1 if follow_up else 0)

        if follow_up_date is not None:
            updates.append("follow_up_date = ?")
            params.append(follow_up_date)

        if closed_date is not None:
            updates.append("closed_date = ?")
            params.append(closed_date)

        if closed_by is not None:
            updates.append("closed_by = ?")
            params.append(closed_by)

        if email_sent is not None:
            updates.append("email_sent = ?")
            params.append(1 if email_sent else 0)

        if email_sent_date is not None:
            updates.append("email_sent_date = ?")
            params.append(email_sent_date)

        if closure_reason is not None:
            updates.append("closure_reason = ?")
            params.append(closure_reason)

        if closure_notes is not None:
            updates.append("closure_notes = ?")
            params.append(closure_notes)

        if closure_reference is not None:
            updates.append("closure_reference = ?")
            params.append(closure_reference)

        if updates:
            query = f"UPDATE events SET {', '.join(updates)} WHERE id = ?"
            params.append(event_id)
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

        return False

def get_ml_policies():
    """Get all ML policies with event counts"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.*,
                   COALESCE(COUNT(pol.event_id), 0) as event_count
            FROM ml_policies p
            LEFT JOIN policies pol ON p.policy_name = pol.policy_name
            GROUP BY p.id, p.policy_name, p.risk_weight, p.category,
                     p.description, p.enabled, p.created_at
            ORDER BY p.policy_name
        """)
        return cursor.fetchall()

def add_ml_policy(policy_name, risk_weight=1.0, category='other', description='', enabled=True):
    """Add new ML policy"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO ml_policies (policy_name, risk_weight, category, description, enabled)
                VALUES (?, ?, ?, ?, ?)
            """, (policy_name, risk_weight, category, description, 1 if enabled else 0))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None

def update_ml_policy(policy_id, policy_name=None, risk_weight=None, category=None, description=None, enabled=None):
    """Update existing ML policy"""
    with get_db() as conn:
        cursor = conn.cursor()

        updates = []
        params = []

        if policy_name is not None:
            updates.append("policy_name = ?")
            params.append(policy_name)

        if risk_weight is not None:
            updates.append("risk_weight = ?")
            params.append(risk_weight)

        if category is not None:
            updates.append("category = ?")
            params.append(category)

        if description is not None:
            updates.append("description = ?")
            params.append(description)

        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)

        if updates:
            params.append(policy_id)
            query = f"UPDATE ml_policies SET {', '.join(updates)} WHERE id = ?"
            try:
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0
            except sqlite3.IntegrityError:
                return False

        return False

def delete_ml_policy(policy_id):
    """Delete ML policy"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ml_policies WHERE id = ?", (policy_id,))
        conn.commit()
        return cursor.rowcount > 0

def get_ml_policy_weights():
    """Get policy weights for ML scoring"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT policy_name, risk_weight
            FROM ml_policies
            WHERE enabled = 1
        """)
        return dict(cursor.fetchall())

def get_closure_reasons():
    """Get all closure reasons"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, reason, requires_reference, enabled, created_at
            FROM closure_reasons
            ORDER BY reason
        """)
        return cursor.fetchall()

def add_closure_reason(reason, requires_reference=False):
    """Add new closure reason"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO closure_reasons (reason, requires_reference)
                VALUES (?, ?)
            """, (reason.strip(), 1 if requires_reference else 0))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None

def update_closure_reason(reason_id, reason=None, requires_reference=None, enabled=None):
    """Update existing closure reason"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        updates = []
        params = []
        
        if reason is not None:
            updates.append("reason = ?")
            params.append(reason.strip())
        
        if requires_reference is not None:
            updates.append("requires_reference = ?")
            params.append(1 if requires_reference else 0)
        
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)
        
        if updates:
            params.append(reason_id)
            query = f"UPDATE closure_reasons SET {', '.join(updates)} WHERE id = ?"
            try:
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0
            except sqlite3.IntegrityError:
                return False
        
        return False

def delete_closure_reason(reason_id):
    """Delete closure reason"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM closure_reasons WHERE id = ?", (reason_id,))
        conn.commit()
        return cursor.rowcount > 0

def get_ml_scoring_rules():
    """Get all ML scoring rules"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, rule_name, condition_field, condition_operator, condition_value, 
                   score_adjustment, enabled, created_at
            FROM ml_scoring_rules
            ORDER BY rule_name
        """)
        return cursor.fetchall()

def add_ml_scoring_rule(rule_name, condition_field, condition_operator, condition_value, score_adjustment):
    """Add new ML scoring rule"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO ml_scoring_rules (rule_name, condition_field, condition_operator, condition_value, score_adjustment)
                VALUES (?, ?, ?, ?, ?)
            """, (rule_name.strip(), condition_field, condition_operator, condition_value, score_adjustment))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None

def update_ml_scoring_rule(rule_id, rule_name=None, condition_field=None, condition_operator=None, 
                          condition_value=None, score_adjustment=None, enabled=None):
    """Update existing ML scoring rule"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        updates = []
        params = []
        
        if rule_name is not None:
            updates.append("rule_name = ?")
            params.append(rule_name.strip())
        
        if condition_field is not None:
            updates.append("condition_field = ?")
            params.append(condition_field)
        
        if condition_operator is not None:
            updates.append("condition_operator = ?")
            params.append(condition_operator)
        
        if condition_value is not None:
            updates.append("condition_value = ?")
            params.append(condition_value)
        
        if score_adjustment is not None:
            updates.append("score_adjustment = ?")
            params.append(score_adjustment)
        
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)
        
        if updates:
            params.append(rule_id)
            query = f"UPDATE ml_scoring_rules SET {', '.join(updates)} WHERE id = ?"
            try:
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0
            except sqlite3.IntegrityError:
                return False
        
        return False

def delete_ml_scoring_rule(rule_id):
    """Delete ML scoring rule"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ml_scoring_rules WHERE id = ?", (rule_id,))
        conn.commit()
        return cursor.rowcount > 0

def clear_database():
    """Delete all rows from all main tables, keeping schema intact."""
    with get_db() as conn:
        cursor = conn.cursor()
        tables = [
            'events', 'recipients', 'attachments', 'policies', 'rules',
            'whitelist_domains', 'whitelist_emails', 'keywords', 'ml_policies', 
            'closure_reasons', 'ml_scoring_rules'
        ]
        for table in tables:
            cursor.execute(f"DELETE FROM {table}")
        conn.commit()
    return True

def clear_events_only():
    """Delete only event data (events, recipients, attachments, policies), keeping rules and configurations intact."""
    with get_db() as conn:
        cursor = conn.cursor()
        # Only delete event-related tables, preserve rules and configurations
        event_tables = ['events', 'recipients', 'attachments', 'policies']
        for table in event_tables:
            cursor.execute(f"DELETE FROM {table}")
        conn.commit()
    return True


def get_high_risk_events(limit=100, offset=0):
    """Get high risk events that haven't been processed by rules"""
    with get_db() as conn:
        cursor = conn.cursor()
        # Simplified query - just return high risk events
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up, trigger_reason,
                   closure_reason, closure_notes, closure_reference,
                   email_sent, email_sent_date
            FROM events
            WHERE ml_score > 0.7 AND status != 'closed' AND is_whitelisted = 0 AND follow_up = 0
            ORDER BY ml_score DESC, datetime(_time) DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return cursor.fetchall()

def get_high_risk_events_count():
    """Get count of high risk events that haven't been processed by rules"""
    with get_db() as conn:
        cursor = conn.cursor()
        # Simplified count query
        cursor.execute("""
            SELECT COUNT(*)
            FROM events
            WHERE ml_score > 0.7 AND status != 'closed' AND is_whitelisted = 0 AND follow_up = 0
        """)
        return cursor.fetchone()[0]

def get_rule_triggered_events(limit=100, offset=0):
    """Get events that have been processed by rules"""
    with get_db() as conn:
        cursor = conn.cursor()
        # For now, return events that have trigger_reason set or are likely rule triggered
        # This is a simplified approach that avoids complex rule evaluation
        cursor.execute("""
            SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                   status, is_whitelisted, follow_up, trigger_reason,
                   closure_reason, closure_notes, closure_reference,
                   email_sent, email_sent_date
            FROM events
            WHERE status != 'closed' AND is_whitelisted = 0 AND follow_up = 0
            AND (trigger_reason IS NOT NULL OR ml_score > 0.8)
            ORDER BY datetime(_time) DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return cursor.fetchall()

def get_rule_triggered_events_count():
    """Get count of events that have been processed by rules"""
    with get_db() as conn:
        cursor = conn.cursor()
        # Simplified count query
        cursor.execute("""
            SELECT COUNT(*)
            FROM events
            WHERE status != 'closed' AND is_whitelisted = 0 AND follow_up = 0
            AND (trigger_reason IS NOT NULL OR ml_score > 0.8)
        """)
        return cursor.fetchone()[0]
