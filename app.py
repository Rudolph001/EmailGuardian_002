import os
import logging
import json
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from models import (
    init_db, get_event_count, get_recent_events, search_events, get_event_detail,
    get_ml_policies, add_ml_policy, update_ml_policy, delete_ml_policy, get_db,
    get_dashboard_stats
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

# Initialize database on startup
with app.app_context():
    init_db()

@app.route("/")
def index():
    """Dashboard/home page"""
    try:
        total_events = get_event_count()
        recent_events = get_recent_events(10)

        # Convert sqlite3.Row objects to regular dicts to avoid comparison issues
        recent_events_list = []
        for event in recent_events:
            recent_events_list.append(dict(event))

        # Get dashboard statistics for all events
        stats = get_dashboard_stats()

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

        if query:
            events_list = search_events(query, limit=100)
        elif filter_type == "whitelisted":
            from models import get_whitelisted_events
            events_list = get_whitelisted_events(100)
        elif filter_type == "follow_up":
            from models import get_follow_up_events
            events_list = get_follow_up_events(100)
        elif filter_type == "closed":
            from models import get_closed_events
            events_list = get_closed_events(100)
        elif filter_type == "high_risk":
            from models import get_high_risk_events
            events_list = get_high_risk_events(100)
        elif filter_type == "rule_triggered":
            from models import get_rule_triggered_events
            events_list = get_rule_triggered_events(100)
        else:
            events_list = get_recent_events(100)

        return render_template("events.html", 
                             events=events_list,
                             query=query,
                             page=page,
                             filter_type=filter_type)
    except Exception as e:
        logger.error(f"Error loading events: {e}")
        flash("Error loading events", "error")
        return render_template("events.html", events=[], query="", page=1, filter_type="all")

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

        return render_template("event_detail.html",
                             event=event_data['event'],
                             recipients=event_data['recipients'],
                             attachments=event_data['attachments'],
                             policies=event_data['policies'],
                             actions=actions,
                             whitelist_matches=whitelist_matches,
                             keyword_matches=keyword_matches)
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

                    if field and operator:  # Only add if field and operator are selected
                        conditions.append({
                            'field': field,
                            'operator': operator,
                            'value': value,
                            'logic': logic
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

@app.route("/event/<int:event_id>/status", methods=["POST"])
def update_event_status(event_id):
    """Update event status"""
    try:
        from models import update_event_status as update_status
        action = request.form.get("action")

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

        elif action == "close":
            if update_status(event_id, status="closed", closed_by="admin"):
                flash("Event closed successfully", "success")
            else:
                flash("Failed to close event", "error")

        elif action == "reopen":
            if update_status(event_id, status="open"):
                flash("Event reopened successfully", "success")
            else:
                flash("Failed to reopen event", "error")

    except Exception as e:
        logger.error(f"Error updating event {event_id} status: {e}")
        flash(f"Error updating event status: {str(e)}", "error")

    return redirect(url_for("event_detail", event_id=event_id))

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    message = None
    if request.method == 'POST' and request.form.get('action') == 'clear_db':
        from models import clear_database
        clear_database()
        message = 'Database cleared successfully.'
    return render_template('admin.html', message=message)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)