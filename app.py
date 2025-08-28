import os
import logging
import json
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from models import (
    init_db, get_event_count, get_recent_events, search_events, get_event_detail,
    get_ml_policies, add_ml_policy, update_ml_policy, delete_ml_policy, get_db,
    get_dashboard_stats, get_closure_reasons
)
from ingest import ingest_csv
from ml import rescore_all_events
from rules import (
    get_rules, add_rule, update_rule, delete_rule,
    get_whitelist_domains, get_whitelist_emails,
    add_whitelist_domain, add_whitelist_email,
    delete_whitelist_domain, delete_whitelist_email,
    get_keywords, add_keyword, delete_keyword,
    apply_rules_to_event, test_rule_against_events
)
from config import SECRET_KEY

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", SECRET_KEY)

# Make functions available to templates
app.jinja_env.globals['get_closure_reasons'] = get_closure_reasons

# Initialize database on startup
with app.app_context():
    init_db()

@app.route("/")
def index():
    """Dashboard/home page"""
    try:
        # Force fresh data retrieval by getting new database connection
        total_events = get_event_count()
        recent_events = get_recent_events(10)

        # Convert sqlite3.Row objects to regular dicts to avoid comparison issues
        recent_events_list = []
        for event in recent_events:
            recent_events_list.append(dict(event))

        # Get fresh dashboard statistics
        stats = get_dashboard_stats()
        
        logger.debug(f"Dashboard stats: {stats}")

        return render_template("index.html", 
                             total_events=total_events,
                             recent_events=recent_events_list,
                             stats=stats)
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        flash("Error loading dashboard", "error")
        return render_template("index.html", total_events=0, recent_events=[], 
                             stats={'high_risk_count': 0, 'low_risk_count': 0, 'whitelisted_count': 0, 
                                   'closed_count': 0, 'rule_triggered_count': 0, 'follow_up_count': 0})

@app.route("/upload", methods=["GET", "POST"])
def upload():
    """CSV upload page"""
    if request.method == "POST":
        try:
            file = request.files.get("csvfile")
            if not file or file.filename == '':
                flash("No file selected", "error")
                return redirect(url_for("upload"))

            # Validate file extension
            if not file.filename.lower().endswith('.csv'):
                flash("Please upload a CSV file", "error")
                return redirect(url_for("upload"))

            logger.info(f"Starting CSV ingestion: {file.filename}")
            stats = ingest_csv(file.stream)

            success_msg = f"Successfully imported {stats['inserted']} events"
            if stats['failed'] > 0:
                success_msg += f" ({stats['failed']} failed - see dead_letter.csv)"

            flash(success_msg, "success")

            # Auto-rescore after import
            try:
                rescore_all_events()
                flash("Risk scores updated", "info")
            except Exception as e:
                logger.warning(f"Auto-rescoring failed: {e}")
                flash("Import successful, but risk scoring failed", "warning")

            return redirect(url_for("events"))

        except Exception as e:
            logger.error(f"CSV upload failed: {e}")
            flash(f"Upload failed: {str(e)}", "error")
            return redirect(url_for("upload"))

    return render_template("upload.html")

@app.route("/events")
def events():
    """Events listing page with search and filtering"""
    try:
        query = request.args.get("q", "").strip()
        filter_type = request.args.get("filter", "all")
        page = int(request.args.get("page", 1))
        per_page = 10  # Set 10 records per page
        offset = (page - 1) * per_page

        # Get total count and events for the current page
        total_events = 0
        events_list = []

        if query:
            events_list = search_events(query, limit=per_page, offset=offset)
            # Get total count for search
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM events
                    WHERE sender LIKE ? OR subject LIKE ?
                """, (f"%{query}%", f"%{query}%"))
                total_events = cursor.fetchone()[0]
        elif filter_type == "whitelisted":
            from models import get_whitelisted_events, get_whitelisted_events_count
            events_list = get_whitelisted_events(per_page, offset)
            total_events = get_whitelisted_events_count()
        elif filter_type == "follow_up":
            from models import get_follow_up_events, get_follow_up_events_count
            events_list = get_follow_up_events(per_page, offset)
            total_events = get_follow_up_events_count()
        elif filter_type == "closed":
            from models import get_closed_events, get_closed_events_count
            events_list = get_closed_events(per_page, offset)
            total_events = get_closed_events_count()
        elif filter_type == "high_risk":
            from models import get_high_risk_events, get_high_risk_events_count
            events_list = get_high_risk_events(per_page, offset)
            total_events = get_high_risk_events_count()
        elif filter_type == "rule_triggered":
            from models import get_rule_triggered_events, get_rule_triggered_events_count
            events_list = get_rule_triggered_events(per_page, offset)
            total_events = get_rule_triggered_events_count()
        else:
            # For "all" events, show everything regardless of categorization
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM events")
                total_events = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT id, _time, sender, subject, ml_score, is_internal_to_external,
                           status, is_whitelisted, follow_up, trigger_reason,
                           closure_reason, closure_notes, closure_reference,
                           email_sent, email_sent_date
                    FROM events
                    ORDER BY datetime(_time) DESC
                    LIMIT ? OFFSET ?
                """, (per_page, offset))
                events_list = cursor.fetchall()

        # Calculate pagination info
        total_pages = (total_events + per_page - 1) // per_page  # Ceiling division
        has_prev = page > 1
        has_next = page < total_pages

        # Get closure reasons for the close modal
        from models import get_closure_reasons
        closure_reasons = get_closure_reasons()

        return render_template("events.html", 
                             events=events_list,
                             query=query,
                             page=page,
                             per_page=per_page,
                             total_events=total_events,
                             total_pages=total_pages,
                             has_prev=has_prev,
                             has_next=has_next,
                             filter_type=filter_type,
                             get_closure_reasons=lambda: closure_reasons)
    except Exception as e:
        logger.error(f"Error loading events: {e}")
        flash("Error loading events", "error")
        return render_template("events.html", events=[], query="", page=1, per_page=10, 
                             total_events=0, total_pages=0, has_prev=False, has_next=False, filter_type="all")

@app.route("/event/<int:event_id>")
def event_detail(event_id):
    """Event detail page"""
    try:
        event_data = get_event_detail(event_id)
        if not event_data:
            flash("Event not found", "error")
            return redirect(url_for("events"))

        # Apply rules to get actions
        try:
            actions = apply_rules_to_event(event_id)
        except Exception as e:
            logger.warning(f"Error applying rules to event {event_id}: {e}")
            actions = []

        # Check whitelist matches
        from rules import check_whitelist_matches
        try:
            whitelist_matches = check_whitelist_matches(event_data['event'], event_data['recipients'])
        except Exception as e:
            logger.warning(f"Error checking whitelist matches for event {event_id}: {e}")
            whitelist_matches = []

        # Check keyword matches
        from rules import check_keyword_matches
        try:
            keyword_matches = check_keyword_matches(event_data['event'])
            logger.debug(f"Found {len(keyword_matches)} keyword matches for event {event_id}")
        except Exception as e:
            logger.error(f"Error checking keyword matches for event {event_id}: {e}")
            keyword_matches = []

        # Get closure reasons for the close modal
        from models import get_closure_reasons
        closure_reasons = get_closure_reasons()

        return render_template("event_detail.html",
                             event=event_data['event'],
                             recipients=event_data['recipients'],
                             attachments=event_data['attachments'],
                             policies=event_data['policies'],
                             actions=actions,
                             whitelist_matches=whitelist_matches,
                             keyword_matches=keyword_matches,
                             closure_reasons=closure_reasons)
    except Exception as e:
        logger.error(f"Error loading event {event_id}: {e}")
        flash("Error loading event details", "error")
        return redirect(url_for("events"))

@app.route("/rules", methods=["GET", "POST"])
def rules():
    """Rules management page"""
    if request.method == 'POST':
        action = request.form.get('action')

        if action in ['add', 'edit']:
            # Create or edit rule
            name = request.form.get('name', '').strip()
            rule_action = request.form.get('rule_action', '').strip()
            priority = int(request.form.get('priority', 100))
            enabled = bool(request.form.get('enabled'))
            rule_id = request.form.get('rule_id') if action == 'edit' else None

            # Parse conditions
            conditions = []
            condition_keys = [k for k in request.form.keys() if k.startswith('conditions[') and k.endswith('][field]')]

            for key in condition_keys:
                # Extract condition index
                import re
                match = re.search(r'conditions\[(\d+)\]', key)
                if match:
                    idx = match.group(1)
                    field = request.form.get(f'conditions[{idx}][field]', '').strip()
                    operator = request.form.get(f'conditions[{idx}][operator]', '').strip()
                    value = request.form.get(f'conditions[{idx}][value]', '').strip()
                    logic = request.form.get(f'conditions[{idx}][logic]', 'AND').strip()
                    negate = bool(request.form.get(f'conditions[{idx}][negate]'))

                    if field and operator:  # Only add if field and operator are selected
                        conditions.append({
                            'field': field,
                            'operator': operator,
                            'value': value,
                            'logic': logic,
                            'negate': negate
                        })

            if name and rule_action:
                try:
                    with get_db() as conn:
                        cursor = conn.cursor()
                        if action == 'edit' and rule_id:
                            cursor.execute("""
                                UPDATE rules 
                                SET name = ?, action = ?, conditions_json = ?, priority = ?, enabled = ?
                                WHERE id = ?
                            """, (name, rule_action, json.dumps(conditions), priority, 1 if enabled else 0, rule_id))
                            flash(f'Rule "{name}" updated successfully!', 'success')
                        else:
                            cursor.execute("""
                                INSERT INTO rules (name, action, conditions_json, priority, enabled)
                                VALUES (?, ?, ?, ?, ?)
                            """, (name, rule_action, json.dumps(conditions), priority, 1 if enabled else 0))
                            flash(f'Rule "{name}" created successfully!', 'success')
                        conn.commit()
                except Exception as e:
                    flash(f'Error {"updating" if action == "edit" else "creating"} rule: {str(e)}', 'danger')
            else:
                flash('Please provide rule name and action.', 'warning')

        elif action == 'delete':
            rule_id = request.form.get('rule_id')
            if rule_id:
                try:
                    with get_db() as conn:
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
                        conn.commit()
                    flash('Rule deleted successfully!', 'success')
                except Exception as e:
                    flash(f'Error deleting rule: {str(e)}', 'danger')

        elif action == 'toggle':
            rule_id = request.form.get('rule_id')
            enabled = request.form.get('enabled') == 'true'
            if rule_id:
                try:
                    with get_db() as conn:
                        cursor = conn.cursor()
                        cursor.execute("UPDATE rules SET enabled = ? WHERE id = ?", 
                                     (1 if enabled else 0, rule_id))
                        conn.commit()
                    flash(f'Rule {"enabled" if enabled else "disabled"} successfully!', 'success')
                except Exception as e:
                    flash(f'Error updating rule: {str(e)}', 'danger')

        elif action == 'test':
            # Test rule against existing events
            try:
                # Parse rule conditions from form data
                conditions_json = request.form.get('conditions')
                if conditions_json:
                    conditions = json.loads(conditions_json)
                else:
                    conditions = []

                # Test the rule against events
                matches, total_events = test_rule_against_events(conditions)

                return jsonify({
                    'success': True,
                    'matches': matches,
                    'total_events': total_events
                })

            except Exception as e:
                logger.error(f"Error testing rule: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                })

        return redirect(url_for('rules'))

    # Get all rules
    rules = get_rules(enabled_only=False)
    return render_template('rules.html', rules=rules)

@app.route("/whitelist", methods=["GET", "POST"])
def whitelist():
    """Whitelist management page"""
    if request.method == "POST":
        try:
            action = request.form.get("action")

            if action == "add_domain":
                domain = request.form.get("domain", "").strip().lower()
                if domain:
                    if add_whitelist_domain(domain):
                        flash(f"Domain '{domain}' added to whitelist", "success")
                    else:
                        flash(f"Domain '{domain}' already whitelisted", "warning")
                else:
                    flash("Domain is required", "error")

            elif action == "add_email":
                email = request.form.get("email", "").strip().lower()
                if email:
                    if add_whitelist_email(email):
                        flash(f"Email '{email}' added to whitelist", "success")
                    else:
                        flash(f"Email '{email}' already whitelisted", "warning")
                else:
                    flash("Email is required", "error")

            elif action == "delete_domain":
                domain_id = int(request.form.get("domain_id"))
                if delete_whitelist_domain(domain_id):
                    flash("Domain removed from whitelist", "success")
                else:
                    flash("Failed to remove domain", "error")

            elif action == "delete_email":
                email_id = int(request.form.get("email_id"))
                if delete_whitelist_email(email_id):
                    flash("Email removed from whitelist", "success")
                else:
                    flash("Failed to remove email", "error")

            elif action == "bulk_add_domains":
                bulk_domains = request.form.get("bulk_domains", "").strip()
                skip_duplicates = request.form.get("skip_duplicates") == "on"

                if bulk_domains:
                    # Handle both newline and pipe separation
                    normalized_input = bulk_domains.replace('|', '\n')
                    lines = [line.strip().lower() for line in normalized_input.split('\n') if line.strip()]

                    if lines:
                        added_count = 0
                        skipped_count = 0
                        failed_count = 0

                        for domain in lines:
                            try:
                                result = add_whitelist_domain(domain)
                                if result:
                                    added_count += 1
                                else:
                                    if skip_duplicates:
                                        skipped_count += 1
                                    else:
                                        failed_count += 1
                            except Exception as e:
                                logger.error(f"Error adding bulk domain '{domain}': {e}")
                                failed_count += 1

                        # Provide detailed feedback
                        messages = []
                        if added_count > 0:
                            messages.append(f"{added_count} domain{'s' if added_count > 1 else ''} added")
                        if skipped_count > 0:
                            messages.append(f"{skipped_count} duplicate{'s' if skipped_count > 1 else ''} skipped")
                        if failed_count > 0:
                            messages.append(f"{failed_count} failed")

                        if added_count > 0:
                            flash(f"Bulk domain import completed: {', '.join(messages)}", "success")
                        elif skipped_count > 0:
                            flash(f"Bulk domain import completed: {', '.join(messages)}", "info")
                        else:
                            flash(f"Bulk domain import failed: {', '.join(messages)}", "error")
                    else:
                        flash("No valid domains found in bulk import", "warning")
                else:
                    flash("Bulk domains are required", "error")

            elif action == "bulk_add_emails":
                bulk_emails = request.form.get("bulk_emails", "").strip()
                skip_duplicates = request.form.get("skip_duplicates") == "on"

                if bulk_emails:
                    # Handle both newline and pipe separation
                    normalized_input = bulk_emails.replace('|', '\n')
                    lines = [line.strip().lower() for line in normalized_input.split('\n') if line.strip()]

                    if lines:
                        added_count = 0
                        skipped_count = 0
                        failed_count = 0

                        for email in lines:
                            try:
                                # Basic email validation
                                if '@' in email and '.' in email.split('@')[-1]:
                                    result = add_whitelist_email(email)
                                    if result:
                                        added_count += 1
                                    else:
                                        if skip_duplicates:
                                            skipped_count += 1
                                        else:
                                            failed_count += 1
                                else:
                                    logger.warning(f"Invalid email format: {email}")
                                    failed_count += 1
                            except Exception as e:
                                logger.error(f"Error adding bulk email '{email}': {e}")
                                failed_count += 1

                        # Provide detailed feedback
                        messages = []
                        if added_count > 0:
                            messages.append(f"{added_count} email{'s' if added_count > 1 else ''} added")
                        if skipped_count > 0:
                            messages.append(f"{skipped_count} duplicate{'s' if skipped_count > 1 else ''} skipped")
                        if failed_count > 0:
                            messages.append(f"{failed_count} failed")

                        if added_count > 0:
                            flash(f"Bulk email import completed: {', '.join(messages)}", "success")
                        elif skipped_count > 0:
                            flash(f"Bulk email import completed: {', '.join(messages)}", "info")
                        else:
                            flash(f"Bulk email import failed: {', '.join(messages)}", "error")
                    else:
                        flash("No valid emails found in bulk import", "warning")
                else:
                    flash("Bulk emails are required", "error")

        except Exception as e:
            logger.error(f"Error managing whitelist: {e}")
            flash(f"Error: {str(e)}", "error")

        return redirect(url_for("whitelist"))

    try:
        domains = get_whitelist_domains()
        emails = get_whitelist_emails()
        return render_template("whitelist.html", domains=domains, emails=emails)
    except Exception as e:
        logger.error(f"Error loading whitelist: {e}")
        flash("Error loading whitelist", "error")
        return render_template("whitelist.html", domains=[], emails=[])

@app.route("/keywords", methods=["GET", "POST"])
def keywords():
    """Keywords management page"""
    if request.method == "POST":
        try:
            action = request.form.get("action")

            if action == "add":
                term = request.form.get("term", "").strip()
                is_regex = request.form.get("is_regex") == "on"

                if term:
                    if add_keyword(term, is_regex):
                        flash(f"Keyword '{term}' added", "success")
                    else:
                        flash(f"Keyword '{term}' already exists", "warning")
                else:
                    flash("Term is required", "error")

            elif action == "bulk_add":
                bulk_terms = request.form.get("bulk_terms", "").strip()
                bulk_is_regex = request.form.get("bulk_is_regex") == "on"
                skip_duplicates = request.form.get("skip_duplicates") == "on"

                if bulk_terms:
                    # Handle both newline and pipe separation
                    normalized_input = bulk_terms.replace('|', '\n')
                    lines = [line.strip() for line in normalized_input.split('\n') if line.strip()]

                    if lines:
                        added_count = 0
                        skipped_count = 0
                        failed_count = 0

                        for term in lines:
                            try:
                                result = add_keyword(term, bulk_is_regex)
                                if result:
                                    added_count += 1
                                else:
                                    if skip_duplicates:
                                        skipped_count += 1
                                    else:
                                        failed_count += 1
                            except Exception as e:
                                logger.error(f"Error adding bulk keyword '{term}': {e}")
                                failed_count += 1

                        # Provide detailed feedback
                        messages = []
                        if added_count > 0:
                            messages.append(f"{added_count} keyword{'s' if added_count > 1 else ''} added")
                        if skipped_count > 0:
                            messages.append(f"{skipped_count} duplicate{'s' if skipped_count > 1 else ''} skipped")
                        if failed_count > 0:
                            messages.append(f"{failed_count} failed")

                        if added_count > 0:
                            flash(f"Bulk import completed: {', '.join(messages)}", "success")
                        elif skipped_count > 0:
                            flash(f"Bulk import completed: {', '.join(messages)}", "info")
                        else:
                            flash(f"Bulk import failed: {', '.join(messages)}", "error")
                    else:
                        flash("No valid keywords found in bulk import", "warning")
                else:
                    flash("Bulk terms are required", "error")

            elif action == "delete":
                keyword_id = int(request.form.get("keyword_id"))
                if delete_keyword(keyword_id):
                    flash("Keyword deleted successfully", "success")
                else:
                    flash("Failed to delete keyword", "error")

        except Exception as e:
            logger.error(f"Error managing keywords: {e}")
            flash(f"Error: {str(e)}", "error")

        return redirect(url_for("keywords"))

    try:
        keywords_list = get_keywords()
        return render_template("keywords.html", keywords=keywords_list)
    except Exception as e:
        logger.error(f"Error loading keywords: {e}")
        flash("Error loading keywords", "error")
        return render_template("keywords.html", keywords=[])

@app.route("/policies", methods=["GET", "POST"])
def policies():
    """ML Policies management page"""
    if request.method == "POST":
        try:
            action = request.form.get("action")

            if action == "auto_populate":
                # Auto-populate policies from existing events
                with get_db() as conn:
                    cursor = conn.cursor()
                    # Get all unique policy names from events
                    cursor.execute("""
                        SELECT DISTINCT policy_name 
                        FROM policies 
                        WHERE policy_name IS NOT NULL AND policy_name != ''
                    """)
                    existing_policies = cursor.fetchall()

                    added_count = 0
                    for policy_row in existing_policies:
                        policy_name = policy_row[0]
                        # Check if already exists in ml_policies
                        cursor.execute("SELECT id FROM ml_policies WHERE policy_name = ?", (policy_name,))
                        if not cursor.fetchone():
                            # Add with default settings
                            cursor.execute("""
                                INSERT INTO ml_policies (policy_name, risk_weight, category, description, enabled)
                                VALUES (?, ?, ?, ?, ?)
                            """, (policy_name, 1.0, 'other', f'Auto-imported policy: {policy_name}', 1))
                            added_count += 1

                    conn.commit()

                if added_count > 0:
                    flash(f"Successfully imported {added_count} policies from existing events", "success")
                else:
                    flash("No new policies found to import", "info")

            elif action == "add":
                policy_name = request.form.get("policy_name", "").strip()
                risk_weight = float(request.form.get("risk_weight", 1.0))
                category = request.form.get("category", "other").strip()
                description = request.form.get("description", "").strip()
                enabled = request.form.get("enabled") == "on"

                if not policy_name:
                    flash("Policy name is required", "error")
                else:
                    policy_id = add_ml_policy(policy_name, risk_weight, category, description, enabled)
                    if policy_id:
                        flash(f"Policy '{policy_name}' created successfully", "success")
                    else:
                        flash(f"Policy '{policy_name}' already exists", "warning")

            elif action == "edit":
                policy_id = int(request.form.get("policy_id"))
                policy_name = request.form.get("policy_name", "").strip()
                risk_weight = float(request.form.get("risk_weight", 1.0))
                category = request.form.get("category", "other").strip()
                description = request.form.get("description", "").strip()
                enabled = request.form.get("enabled") == "on"

                if update_ml_policy(policy_id, policy_name, risk_weight, category, description, enabled):
                    flash(f"Policy '{policy_name}' updated successfully", "success")
                else:
                    flash("Failed to update policy", "error")

            elif action == "delete":
                policy_id = int(request.form.get("policy_id"))
                if delete_ml_policy(policy_id):
                    flash("Policy deleted successfully", "success")
                else:
                    flash("Failed to delete policy", "error")

        except Exception as e:
            logger.error(f"Error managing policies: {e}")
            flash(f"Error: {str(e)}", "error")

        return redirect(url_for("policies"))

    try:
        policies_list = get_ml_policies()
        return render_template("policies.html", policies=policies_list)
    except Exception as e:
        logger.error(f"Error loading policies: {e}")
        flash("Error loading policies", "error")
        return render_template("policies.html", policies=[])

@app.route("/rescore", methods=["POST"])
def rescore():
    """Trigger ML rescoring of all events"""
    try:
        rescore_all_events()
        flash("All events rescored successfully", "success")
    except Exception as e:
        logger.error(f"Rescoring failed: {e}")
        flash(f"Rescoring failed: {str(e)}", "error")

    return redirect(url_for("index"))

@app.route("/process_rules", methods=["POST"])
def process_rules():
    """Process all events to apply rules and set trigger reasons"""
    try:
        # Check if this is an AJAX request
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            # Start processing in background and return immediately
            import threading
            from rules import process_all_events_for_rules_with_progress
            
            # Reset progress tracking
            app.config['rule_processing'] = {
                'in_progress': True,
                'processed_count': 0,
                'triggered_count': 0,
                'total_events': 0,
                'completed': False,
                'error': None
            }
            
            def background_process():
                try:
                    processed_count, triggered_count = process_all_events_for_rules_with_progress()
                    app.config['rule_processing'].update({
                        'completed': True,
                        'processed_count': processed_count,
                        'triggered_count': triggered_count
                    })
                except Exception as e:
                    logger.error(f"Background rule processing failed: {e}")
                    app.config['rule_processing'].update({
                        'completed': True,
                        'error': str(e)
                    })
            
            thread = threading.Thread(target=background_process)
            thread.daemon = True
            thread.start()
            
            return jsonify({'success': True, 'message': 'Processing started'})
        else:
            # Traditional form submission - process synchronously
            from rules import process_all_events_for_rules
            processed_count, triggered_count = process_all_events_for_rules()
            flash(f"Processed {processed_count} events. {triggered_count} events had rules triggered.", "success")
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"Error processing rules: {e}")
        if request.is_json or request.headers.get('Content-Type') == 'application/json':
            return jsonify({'success': False, 'error': str(e)})
        else:
            flash(f"Error processing rules: {e}", "error")
            return redirect(url_for('index'))

@app.route("/process_rules_progress", methods=["GET"])
def process_rules_progress():
    """Get progress of rule processing"""
    progress = app.config.get('rule_processing', {
        'in_progress': False,
        'processed_count': 0,
        'triggered_count': 0,
        'total_events': 0,
        'completed': False,
        'error': None
    })
    
    return jsonify(progress)

@app.route("/event/<int:event_id>/status", methods=["POST"])
def update_event_status(event_id):
    """Update event status"""
    try:
        from models import update_event_status as update_status
        action = request.form.get("action")
        redirect_to = request.form.get("redirect_to", "event_detail")

        if action == "whitelist":
            if update_status(event_id, is_whitelisted=True):
                flash("Event whitelisted successfully", "success")
            else:
                flash("Failed to whitelist event", "error")

        elif action == "follow_up":
            from datetime import datetime
            follow_up_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if update_status(event_id, follow_up=True, follow_up_date=follow_up_date):
                flash("Event marked for follow-up", "success")
            else:
                flash("Failed to mark event for follow-up", "error")

        elif action == "clear":
            # Clear means close the event (move to Closed status)
            if update_status(event_id, status="closed", closed_by="admin"):
                flash("Event cleared and moved to Closed", "success")
            else:
                flash("Failed to clear event", "error")

        elif action == "close":
            closure_reason = request.form.get("closure_reason", "").strip()
            closure_notes = request.form.get("closure_notes", "").strip()
            closure_reference = request.form.get("closure_reference", "").strip()

            if update_status(event_id, status="closed", closed_by="admin", 
                           closure_reason=closure_reason, closure_notes=closure_notes,
                           closure_reference=closure_reference, follow_up=False):
                flash("Event closed successfully", "success")
            else:
                flash("Failed to close event", "error")

        elif action == "reopen":
            if update_status(event_id, status="open"):
                flash("Event reopened successfully", "success")
            else:
                flash("Failed to reopen event", "error")

        elif action == "mark_email_sent":
            from datetime import datetime
            email_sent_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if update_status(event_id, email_sent=True, email_sent_date=email_sent_date):
                flash("Email marked as sent successfully", "success")
            else:
                flash("Failed to mark email as sent", "error")

    except Exception as e:
        logger.error(f"Error updating event {event_id} status: {e}")
        flash(f"Error updating event status: {str(e)}", "error")

    # Handle different redirect destinations
    if redirect_to == "events":
        return redirect(url_for("events"))
    else:
        return redirect(url_for("event_detail", event_id=event_id))

@app.route("/api/classify_domains/<int:event_id>")
def classify_event_domains_api(event_id):
    """API endpoint to classify domains for an event"""
    try:
        from domain_ml import classify_event_domains, get_domain_risk_score
        
        domain_classifications = classify_event_domains(event_id)
        domain_risk_score = get_domain_risk_score(domain_classifications)
        
        return jsonify({
            'success': True,
            'domain_classifications': domain_classifications,
            'domain_risk_score': domain_risk_score
        })
        
    except Exception as e:
        logger.error(f"Error classifying domains for event {event_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route("/batch_update_events", methods=["POST"])
def batch_update_events():
    """Batch update multiple events"""
    try:
        event_ids_str = request.form.get("event_ids", "")
        action = request.form.get("action")
        redirect_to = request.form.get("redirect_to", "events")

        if not event_ids_str or not action:
            flash("Invalid batch update request", "error")
            return redirect(url_for("index"))

        event_ids = [int(id.strip()) for id in event_ids_str.split(",") if id.strip()]

        if not event_ids:
            flash("No events selected for batch update", "error")
            return redirect(url_for("index"))

        from models import update_event_status as update_status
        from datetime import datetime

        success_count = 0

        for event_id in event_ids:
            try:
                if action == "whitelist":
                    if update_status(event_id, is_whitelisted=True):
                        success_count += 1

                elif action == "follow_up":
                    follow_up_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if update_status(event_id, follow_up=True, follow_up_date=follow_up_date):
                        success_count += 1

                elif action == "clear":
                    if update_status(event_id, status="closed", closed_by="admin"):
                        success_count += 1

            except Exception as e:
                logger.error(f"Error updating event {event_id} in batch: {e}")
                continue

        # Provide feedback
        total_events = len(event_ids)
        if success_count == total_events:
            action_names = {
                'whitelist': 'whitelisted',
                'follow_up': 'marked for follow-up',
                'clear': 'cleared and moved to closed'
            }
            flash(f"Successfully {action_names[action]} {success_count} event{'s' if success_count > 1 else ''}", "success")
        elif success_count > 0:
            flash(f"Partially successful: {success_count}/{total_events} events updated", "warning")
        else:
            flash(f"Failed to update any of the {total_events} selected events", "error")

    except Exception as e:
        logger.error(f"Batch update failed: {e}")
        flash(f"Batch update failed: {str(e)}", "error")

    # Handle different redirect destinations
    if redirect_to == "index":
        return redirect(url_for("index"))
    else:
        return redirect(url_for("events"))

@app.route("/domain_labels", methods=["GET", "POST"])
def domain_labels():
    """Domain labeling interface for training the ML classifier"""
    if request.method == "POST":
        try:
            action = request.form.get("action")
            
            if action == "label_domain":
                domain = request.form.get("domain", "").strip().lower()
                label = int(request.form.get("label"))
                confidence = float(request.form.get("confidence", 1.0))
                
                if domain and 0 <= label <= 3:
                    with get_db() as conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            INSERT OR REPLACE INTO domain_labels 
                            (domain, label, confidence, updated_at) 
                            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        """, (domain, label, confidence))
                        conn.commit()
                    
                    label_names = {0: 'Internal', 1: 'Freemail', 2: 'Partner', 3: 'Suspicious'}
                    flash(f"Domain '{domain}' labeled as {label_names[label]}", "success")
                else:
                    flash("Invalid domain or label", "error")
            
            elif action == "train_classifier":
                from domain_ml import train_domain_classifier
                if train_domain_classifier():
                    flash("Domain classifier trained successfully", "success")
                else:
                    flash("Failed to train domain classifier", "error")
            
            elif action == "classify_unlabeled":
                # Auto-classify unlabeled domains
                from domain_ml import domain_classifier
                
                # Load or train classifier
                if not domain_classifier.model:
                    domain_classifier.load_model()
                
                if not domain_classifier.model:
                    flash("Domain classifier not available. Please train it first.", "warning")
                else:
                    with get_db() as conn:
                        cursor = conn.cursor()
                        
                        # Get unlabeled domains
                        cursor.execute("""
                            SELECT DISTINCT email FROM recipients r
                            WHERE NOT EXISTS (
                                SELECT 1 FROM domain_labels dl 
                                WHERE dl.domain = LOWER(SUBSTR(r.email, INSTR(r.email, '@') + 1))
                            )
                            LIMIT 50
                        """)
                        
                        emails = cursor.fetchall()
                        classified_count = 0
                        
                        for email_row in emails:
                            from utils import extract_domain
                            domain = extract_domain(email_row[0])
                            
                            if domain:
                                classification = domain_classifier.classify_domain(domain)
                                
                                # Only auto-label if confidence > 0.8
                                if classification['confidence'] > 0.8:
                                    label_map = {'internal': 0, 'freemail': 1, 'partner': 2, 'suspicious': 3}
                                    label_num = label_map.get(classification['label'])
                                    
                                    if label_num is not None:
                                        cursor.execute("""
                                            INSERT OR IGNORE INTO domain_labels 
                                            (domain, label, confidence) 
                                            VALUES (?, ?, ?)
                                        """, (domain, label_num, classification['confidence']))
                                        classified_count += 1
                        
                        conn.commit()
                        flash(f"Auto-classified {classified_count} domains", "info")
            
        except Exception as e:
            logger.error(f"Error managing domain labels: {e}")
            flash(f"Error: {str(e)}", "error")
        
        return redirect(url_for("domain_labels"))
    
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Create domain_labels table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domain_labels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    label INTEGER NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Get labeled domains
            cursor.execute("""
                SELECT id, domain, label, confidence, created_at, updated_at
                FROM domain_labels 
                ORDER BY updated_at DESC
                LIMIT 100
            """)
            labeled_domains = cursor.fetchall()
            
            # Get some unlabeled domains
            cursor.execute("""
                SELECT DISTINCT LOWER(SUBSTR(email, INSTR(email, '@') + 1)) as domain,
                       COUNT(*) as email_count
                FROM recipients r
                WHERE NOT EXISTS (
                    SELECT 1 FROM domain_labels dl 
                    WHERE dl.domain = LOWER(SUBSTR(r.email, INSTR(r.email, '@') + 1))
                )
                GROUP BY domain
                ORDER BY email_count DESC
                LIMIT 20
            """)
            unlabeled_domains = cursor.fetchall()
            
        label_names = {0: 'Internal', 1: 'Freemail', 2: 'Partner', 3: 'Suspicious'}
        
        return render_template("domain_labels.html", 
                             labeled_domains=labeled_domains,
                             unlabeled_domains=unlabeled_domains,
                             label_names=label_names)
    except Exception as e:
        logger.error(f"Error loading domain labels: {e}")
        flash("Error loading domain labels", "error")
        return render_template("domain_labels.html", labeled_domains=[], unlabeled_domains=[], label_names={})

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    from models import (get_closure_reasons, add_closure_reason, 
                       update_closure_reason, delete_closure_reason, clear_database, clear_events_only,
                       get_ml_scoring_rules, add_ml_scoring_rule, update_ml_scoring_rule, delete_ml_scoring_rule)

    message = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'clear_db':
            clear_database()
            message = 'Database cleared successfully.'

        elif action == 'clear_events':
            clear_events_only()
            flash('All imported events deleted successfully. Rules and configurations preserved.', 'success')

        elif action == 'add_reason':
            reason = request.form.get('reason', '').strip()
            requires_reference = request.form.get('requires_reference') == 'on'

            if reason:
                if add_closure_reason(reason, requires_reference):
                    flash(f"Closure reason '{reason}' added successfully", "success")
                else:
                    flash(f"Closure reason '{reason}' already exists", "warning")
            else:
                flash("Reason is required", "error")

        elif action == 'edit_reason':
            reason_id = int(request.form.get('reason_id'))
            reason = request.form.get('reason', '').strip()
            requires_reference = request.form.get('requires_reference') == 'on'
            enabled = request.form.get('enabled') == 'on'

            if update_closure_reason(reason_id, reason, requires_reference, enabled):
                flash(f"Closure reason updated successfully", "success")
            else:
                flash("Failed to update closure reason", "error")

        elif action == 'delete_reason':
            reason_id = int(request.form.get('reason_id'))
            if delete_closure_reason(reason_id):
                flash("Closure reason deleted successfully", "success")
            else:
                flash("Failed to delete closure reason", "error")

        elif action == 'add_ml_rule':
            rule_name = request.form.get('rule_name', '').strip()
            condition_field = request.form.get('condition_field', '').strip()
            condition_operator = request.form.get('condition_operator', '').strip()
            condition_value = request.form.get('condition_value', '').strip()
            score_adjustment = float(request.form.get('score_adjustment', 0))

            if rule_name and condition_field and condition_operator:
                if add_ml_scoring_rule(rule_name, condition_field, condition_operator, condition_value, score_adjustment):
                    flash(f"ML scoring rule '{rule_name}' added successfully", "success")
                else:
                    flash(f"ML scoring rule '{rule_name}' already exists", "warning")
            else:
                flash("Rule name, field, and operator are required", "error")

        elif action == 'edit_ml_rule':
            rule_id = int(request.form.get('ml_rule_id'))
            rule_name = request.form.get('rule_name', '').strip()
            condition_field = request.form.get('condition_field', '').strip()
            condition_operator = request.form.get('condition_operator', '').strip()
            condition_value = request.form.get('condition_value', '').strip()
            score_adjustment = float(request.form.get('score_adjustment', 0))
            enabled = request.form.get('enabled') == 'on'

            if update_ml_scoring_rule(rule_id, rule_name, condition_field, condition_operator, 
                                     condition_value, score_adjustment, enabled):
                flash("ML scoring rule updated successfully", "success")
            else:
                flash("Failed to update ML scoring rule", "error")

        elif action == 'delete_ml_rule':
            rule_id = int(request.form.get('ml_rule_id'))
            if delete_ml_scoring_rule(rule_id):
                flash("ML scoring rule deleted successfully", "success")
            else:
                flash("Failed to delete ML scoring rule", "error")

        return redirect(url_for('admin_dashboard'))

    closure_reasons = get_closure_reasons()
    ml_scoring_rules = get_ml_scoring_rules()
    return render_template('admin.html', message=message, closure_reasons=closure_reasons, ml_scoring_rules=ml_scoring_rules)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)