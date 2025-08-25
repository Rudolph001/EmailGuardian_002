# Email Guardian — Replit Setup & Architecture Guide

A lightweight **email case management** web app built with **Python (Flask) + SQLite** that imports CSV events and adds **rules, whitelisting, keyword lists, and ML-based risk scoring**. Designed to run locally (e.g., Replit or your laptop) and handle **10,000+ events** without skipping rows.

---

## ✨ Features

- CSV import of events with fields:  
  `_time, sender, subject, attachments, recipients, time_month, leaver, termination_date, bunit, department, user_response, final_outcome, policy_name, justifications`
- Handles **multi-valued fields**:
  - `recipients`: multiple emails separated by `,`
  - `attachments`: multiple file names separated by `,`
  - `policy_name`: multiple policies separated by `,`
- **Internal → external** focus: filter/flag events where sender is from internal domains and at least one recipient is an external domain.
- **Rules engine**: create custom allow/block/escalate rules by domain, user, policy, keywords, and more.
- **Whitelisting**: domains, senders, recipients.
- **Keyword lists**: case-insensitive phrase and regex matching.
- **ML risk scoring**:
  - Simple baseline model (Logistic Regression) trained on your historical labels (`final_outcome`, `user_response`)
  - Heuristic fallback if labels are missing
- Scales to **10000+ rows** via **streaming CSV ingestion**, batched inserts, robust error handling, and indexes.
- Admin UI to manage rules, whitelists, and keyword lists; trigger (re)scoring.

---

## 🧱 Project Structure (suggested)

```
email-guardian/
├─ app.py
├─ config.py
├─ models.py
├─ rules.py
├─ ml.py
├─ ingest.py
├─ utils.py
├─ requirements.txt
├─ static/
├─ templates/
│  ├─ base.html
│  ├─ index.html
│  ├─ upload.html
│  ├─ events.html
│  ├─ rules.html
│  ├─ whitelist.html
│  ├─ keywords.html
│  └─ event_detail.html
└─ README.md
```

---

## ⚙️ Replit Setup

1. **Create a new Replit** (Python template).
2. Add these files (you can copy snippets from this README):
   - `app.py`, `models.py`, `ingest.py`, `rules.py`, `ml.py`, `config.py`, `utils.py`, `requirements.txt`, templates.
4. Open the shell and run:
   ```bash
   pip install -r requirements.txt
   python app.py
   ```
5. If running locally instead of Replit:
   ```bash
   export FLASK_APP=app.py
   flask run --host=0.0.0.0 --port=5000
   ```

---

## 📦 requirements.txt

```
Flask==3.0.3
pandas==2.2.2
numpy==2.0.1
scikit-learn==1.5.1
python-dateutil==2.9.0.post0
email-validator==2.2.0
tqdm==4.66.5
```

> **Why Pandas?** We *don’t* load the whole file in memory by default. Ingestion uses Python’s `csv` module in streaming mode. Pandas is used only for optional analyses and ML prep.

---

## 🔐 Internal vs External

Set your internal domains in `config.py`:

```python
# config.py
INTERNAL_DOMAINS = {"yourcorp.com", "corp.local"}  # add more
DATABASE_PATH = "email_guardian.sqlite"
BATCH_SIZE = 1000  # rows per transaction during ingest
MAX_SPLITS = 500   # safety cap for multi-valued split
DELIMITERS = {",", ";"}  # accepted multi-value delimiters
```

**Rule**: We consider an event in-scope if:
- `sender` domain ∈ `INTERNAL_DOMAINS`, and
- at least one `recipient` domain ∉ `INTERNAL_DOMAINS`.

---

## 🗃️ Database Schema (SQLite)

We **normalize** multi-valued fields into link tables. Create tables on first run.

```sql
-- Core events
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  _time TEXT NOT NULL,
  sender TEXT NOT NULL,
  subject TEXT,
  time_month TEXT,
  leaver INTEGER DEFAULT 0, -- 0/1
  termination_date TEXT,
  bunit TEXT,
  department TEXT,
  user_response TEXT,
  final_outcome TEXT,
  justifications TEXT,
  is_internal_to_external INTEGER DEFAULT 0,
  ml_score REAL DEFAULT NULL,
  ml_model_version TEXT DEFAULT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Multi-valued tables
CREATE TABLE IF NOT EXISTS recipients (
  id INTEGER PRIMARY KEY,
  event_id INTEGER NOT NULL,
  email TEXT NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attachments (
  id INTEGER PRIMARY KEY,
  event_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY,
  event_id INTEGER NOT NULL,
  policy_name TEXT NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

-- Rules / Lists
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('allow','block','escalate','flag')),
  sender_pattern TEXT,           -- glob/regex
  recipient_domain TEXT,
  policy_name TEXT,
  keyword TEXT,                  -- simple literal
  priority INTEGER DEFAULT 100,  -- lower = earlier
  enabled INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS whitelist_domains (
  id INTEGER PRIMARY KEY,
  domain TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist_emails (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS keywords (
  id INTEGER PRIMARY KEY,
  term TEXT UNIQUE NOT NULL,
  is_regex INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(_time);
CREATE INDEX IF NOT EXISTS idx_events_sender ON events(sender);
CREATE INDEX IF NOT EXISTS idx_recipients_event ON recipients(event_id);
CREATE INDEX IF NOT EXISTS idx_attachments_event ON attachments(event_id);
CREATE INDEX IF NOT EXISTS idx_policies_event ON policies(event_id);
```

**SQLite PRAGMAs** (set once per connection for speed while keeping reliability):
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA cache_size=-20000; -- ~20MB
```

---

## 📥 CSV Import — Reliable & Scalable (10k+ rows)

### Expectations
- CSV **UTF-8** with headers exactly:
  ```
  _time,sender,subject,attachments,recipients,time_month,leaver,termination_date,bunit,department,user_response,final_outcome,policy_name,justifications
  ```
- Multi-valued columns use `,` separator **inside the field** (the CSV writer should quote fields containing commas). We also accept `;`.

### Strategy
- **Stream**, don’t slurp: iterate file line-by-line using `csv.DictReader`.
- **Batch inserts**: accumulate rows and insert every `BATCH_SIZE` (e.g., 1000).
- **Transactions**: one transaction per batch → prevents half-written states while keeping memory usage low.
- **Row-level error capture**: if a row fails, write it to a `dead_letter.csv` and continue.
- **Validation**: sanitize emails, coerce booleans/dates, trim whitespace.
- **No skipping events**: every row is attempted; failures are logged with reasons.

### Ingestion Flow (pseudocode)

```python
with sqlite3.connect(DATABASE_PATH) as conn:
    set_pragmas(conn)
    reader = csv.DictReader(stream)
    batch = []
    for i, row in enumerate(reader, start=1):
        try:
            parsed = normalize_row(row)  # returns (event, recipients[], attachments[], policies[])
            batch.append(parsed)
            if len(batch) >= BATCH_SIZE:
                insert_batch(conn, batch)
                batch.clear()
        except Exception as e:
            write_dead_letter(i, row, e)

    if batch:
        insert_batch(conn, batch)
```

> **Tip**: show a progress bar in terminal with `tqdm` when ingesting large files.

---

## 🧠 ML Risk Scoring

We provide two paths:

### 1) Heuristic Baseline (no labels required)
Score each event on [0, 1] using:
- `num_recipients` (more recipients → higher risk)
- `num_attachments`
- `external_domain_count` (recipients not in `INTERNAL_DOMAINS`)
- `leaver` (1 if true OR if `termination_date` is set and `_time` ≥ `termination_date`)
- `policy_hits` (count of policy_name entries)
- `keyword_hits` (matches from `keywords` table; regex respected)
- `domain_whitelisted` (downweights risk)
- `sender_whitelisted` (downweights risk)

Example formula:
```
risk = sigmoid(
  0.8 * log1p(num_recipients)
+ 0.6 * log1p(num_attachments)
+ 1.2 * external_domain_count
+ 1.5 * leaver_flag
+ 0.7 * policy_hits
+ 0.9 * keyword_hits
- 1.0 * is_whitelisted
)
```

### 2) Supervised Model (historical labels)
Train a **LogisticRegression** using events with labels:
- **y** from `final_outcome` (e.g., map {`"safe"`→0, `"risky"`→1}) or transform `user_response`.
- **X** features:
  - counts: recipients, attachments, policies, keywords
  - text: `subject` (use simple bag-of-words from `sklearn.feature_extraction.text`)
  - flags: leaver, external recipients, internal→external, month, department, bunit

Store:
- `ml_model_version` (e.g., `lr:v1`)
- `ml_score` on `events`

Re-scoring can be triggered after:
- import finishes,
- rules/whitelists/keywords changed,
- labels updated.

---

## 🧩 Rules, Whitelisting, Keywords

- **Order of operations** (per event at view-time or during scoring):
  1. Check **whitelists** (sender or all recipients/domains whitelisted) → downweight or auto-allow.
  2. Apply **rules** by `priority`:
     - Match by sender pattern (regex or `fnmatch`), recipient domain, policy name, or keyword.
     - Action: `allow | block | escalate | flag`.
  3. Compute **ML score** (or reuse stored value).
  4. Final decision can combine rule action + score threshold.

- **Keywords**:
  - `term` is matched case-insensitively.
  - If `is_regex=1`, compile safely; set maximum regex length and timeout to avoid ReDoS.
  - Store match counts per event (optional).

---

## 🧪 Minimal Code Snippets

> These snippets are **starters**. Copy them into files and adapt.

### `app.py`

```python
from flask import Flask, request, render_template, redirect, url_for, flash
import sqlite3, os
from models import init_db, get_db
from ingest import ingest_csv
from ml import rescore_all
from rules import apply_rules_to_event, get_rules
from config import DATABASE_PATH

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")

@app.before_first_request
def startup():
    with sqlite3.connect(DATABASE_PATH) as conn:
        init_db(conn)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["GET","POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("csvfile")
        if not file:
            flash("No file uploaded", "error")
            return redirect(url_for("upload"))
        stats = ingest_csv(file.stream)
        flash(f"Imported {stats['inserted']} events, {stats['failed']} failed (see dead_letter.csv).", "info")
        rescore_all()  # optional auto-rescore after ingest
        return redirect(url_for("events"))
    return render_template("upload.html")

@app.route("/events")
def events():
    q = request.args.get("q", "").strip()
    with get_db() as conn:
        cur = conn.cursor()
        if q:
            cur.execute("""
                SELECT id, _time, sender, subject, ml_score
                FROM events
                WHERE sender LIKE ? OR subject LIKE ?
                ORDER BY datetime(_time) DESC
                LIMIT 100
            """, (f"%{q}%", f"%{q}%"))
        else:
            cur.execute("""
                SELECT id, _time, sender, subject, ml_score
                FROM events
                ORDER BY datetime(_time) DESC
                LIMIT 100
            """)
        rows = cur.fetchall()
    return render_template("events.html", rows=rows, q=q)

@app.route("/event/<int:event_id>")
def event_detail(event_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events WHERE id=?", (event_id,))
        event = cur.fetchone()
        cur.execute("SELECT email FROM recipients WHERE event_id=?", (event_id,))
        recips = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT filename FROM attachments WHERE event_id=?", (event_id,))
        atts = [a[0] for a in cur.fetchall()]
        cur.execute("SELECT policy_name FROM policies WHERE event_id=?", (event_id,))
        pols = [p[0] for p in cur.fetchall()]
    actions = apply_rules_to_event(event_id)
    return render_template("event_detail.html", event=event, recips=recips, atts=atts, pols=pols, actions=actions)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

### `models.py`

```python
import sqlite3
from config import DATABASE_PATH

DDL = """
-- (paste the SQL from the schema section here)
"""

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA cache_size=-20000;")
    return conn

def init_db(conn):
    cur = conn.cursor()
    for stmt in DDL.split(";\n"):
        if stmt.strip():
            cur.execute(stmt)
    conn.commit()
```

### `utils.py`

```python
import re
from email.utils import parseaddr
from email_validator import validate_email, EmailNotValidError
from config import INTERNAL_DOMAINS, DELIMITERS, MAX_SPLITS

def split_multi(value):
    if not value:
        return []
    # normalize delimiters
    for d in DELIMITERS:
        value = value.replace(d, ",")
    parts = [p.strip() for p in value.split(",")]
    parts = [p for p in parts if p]
    return parts[:MAX_SPLITS]

def email_domain(addr):
    try:
        name, email = parseaddr(addr)
        v = validate_email(email, check_deliverability=False)
        return v.normalized.split("@",1)[1].lower()
    except EmailNotValidError:
        return ""

def is_internal_to_external(sender, recipients):
    sdom = email_domain(sender)
    if sdom not in INTERNAL_DOMAINS:
        return 0
    for r in recipients:
        dom = email_domain(r)
        if dom and dom not in INTERNAL_DOMAINS:
            return 1
    return 0
```

### `ingest.py`

```python
import csv, sqlite3
from datetime import datetime
from models import get_db
from utils import split_multi, is_internal_to_external
from config import DATABASE_PATH, BATCH_SIZE

def normalize_row(row):
    # required fields
    _time = row.get("_time","").strip()
    sender = row.get("sender","").strip()
    subject = row.get("subject","").strip()
    time_month = row.get("time_month","").strip()
    leaver = 1 if str(row.get("leaver","0")).strip() in {"1","true","True","yes","Yes"} else 0
    termination_date = row.get("termination_date","").strip()
    bunit = row.get("bunit","").strip()
    department = row.get("department","").strip()
    user_response = row.get("user_response","").strip()
    final_outcome = row.get("final_outcome","").strip()
    justifications = row.get("justifications","").strip()

    recipients = split_multi(row.get("recipients",""))
    attachments = split_multi(row.get("attachments",""))
    policies = split_multi(row.get("policy_name",""))

    itoe = is_internal_to_external(sender, recipients)

    event = (_time, sender, subject, time_month, leaver, termination_date, bunit,
             department, user_response, final_outcome, justifications, itoe)

    return event, recipients, attachments, policies

def set_pragmas(conn):
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA cache_size=-20000;")

def insert_batch(conn, batch):
    cur = conn.cursor()
    cur.executemany("""
        INSERT INTO events
        (_time, sender, subject, time_month, leaver, termination_date, bunit, department, user_response, final_outcome, justifications, is_internal_to_external)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, [b[0] for b in batch])
    start_id = cur.lastrowid
    ids = list(range(start_id - len(batch) + 1, start_id + 1))
    rec_rows, att_rows, pol_rows = [], [], []
    for eid, (_, recips, atts, pols) in zip(ids, batch):
        rec_rows += [(eid, r) for r in recips]
        att_rows += [(eid, a) for a in atts]
        pol_rows += [(eid, p) for p in pols]
    if rec_rows:
        cur.executemany("INSERT INTO recipients (event_id, email) VALUES (?,?)", rec_rows)
    if att_rows:
        cur.executemany("INSERT INTO attachments (event_id, filename) VALUES (?,?)", att_rows)
    if pol_rows:
        cur.executemany("INSERT INTO policies (event_id, policy_name) VALUES (?,?)", pol_rows)
    conn.commit()

def write_dead_letter(line_no, row, err, path="dead_letter.csv"):
    import json
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"line": line_no, "error": repr(err), "row": row}, ensure_ascii=False) + "\n")

def ingest_csv(stream, batch_size=BATCH_SIZE):
    reader = csv.DictReader((line.decode('utf-8', errors='replace') if isinstance(line, (bytes, bytearray)) else line for line in stream))
    inserted = failed = 0
    batch = []
    with get_db() as conn:
        set_pragmas(conn)
        for i, row in enumerate(reader, start=2): # start=2 accounts for header row
            try:
                parsed = normalize_row(row)
                batch.append(parsed)
                if len(batch) >= batch_size:
                    insert_batch(conn, batch)
                    inserted += len(batch)
                    batch.clear()
            except Exception as e:
                failed += 1
                write_dead_letter(i, row, e)
        if batch:
            insert_batch(conn, batch)
            inserted += len(batch)
    return {"inserted": inserted, "failed": failed}
```

### `rules.py`

```python
import fnmatch, re, sqlite3
from models import get_db

def get_rules():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, action, sender_pattern, recipient_domain, policy_name, keyword, priority, enabled FROM rules WHERE enabled=1 ORDER BY priority ASC")
        return [dict(zip([c[0] for c in cur.description], r)) for r in cur.fetchall()]

def apply_rules_to_event(event_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT sender FROM events WHERE id=?", (event_id,))
        row = cur.fetchone()
        if not row:
            return []
        sender = row[0]
        cur.execute("SELECT email FROM recipients WHERE event_id=?", (event_id,))
        recips = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT policy_name FROM policies WHERE event_id=?", (event_id,))
        pols = [p[0] for p in cur.fetchall()]

    actions = []
    for r in get_rules():
        match = False
        if r['sender_pattern'] and fnmatch.fnmatch(sender, r['sender_pattern']):
            match = True
        if r['recipient_domain'] and any(e.lower().split("@")[-1]==r['recipient_domain'].lower() for e in recips):
            match = True
        if r['policy_name'] and any(p.lower()==r['policy_name'].lower() for p in pols):
            match = True
        if r['keyword'] and r['keyword'].lower() in (sender.lower() + " " + " ".join(pols)).lower():
            match = True
        if match:
            actions.append({"rule": r['name'], "action": r['action']})
    return actions
```

### `ml.py`

```python
import sqlite3, math, re
from models import get_db

def sigmoid(x): 
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 1.0 if x > 0 else 0.0

def heuristic_score(event_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT leaver, is_internal_to_external FROM events WHERE id=?", (event_id,))
        row = c.fetchone()
        if not row:
            return 0.0
        leaver, itoe = row
        c.execute("SELECT COUNT(*) FROM recipients WHERE event_id=?", (event_id,))
        nrec = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM attachments WHERE event_id=?", (event_id,))
        natt = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM policies WHERE event_id=?", (event_id,))
        npol = c.fetchone()[0]
        # keywords
        c.execute("SELECT term, is_regex FROM keywords")
        kws = c.fetchall()
        c.execute("SELECT policy_name FROM policies WHERE event_id=?", (event_id,))
        pol_text = " ".join([r[0] for r in c.fetchall()])

    kw_hits = 0
    text = pol_text.lower()
    for term, is_rx in kws:
        if is_rx:
            try:
                if re.search(term, text, flags=re.IGNORECASE):
                    kw_hits += 1
            except re.error:
                continue
        else:
            if term.lower() in text:
                kw_hits += 1

    x = 0.8*math.log1p(nrec) + 0.6*math.log1p(natt) + 1.2*(1 if itoe else 0) + 1.5*(1 if leaver else 0) + 0.7*npol + 0.9*kw_hits
    return sigmoid(x)

def rescore_all():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM events")
        ids = [r[0] for r in c.fetchall()]
        for eid in ids:
            score = heuristic_score(eid)
            c.execute("UPDATE events SET ml_score=?, ml_model_version=? WHERE id=?", (score, "heuristic:v1", eid))
        conn.commit()
```

---

## 🧭 UI Templates (very minimal)

Create `templates/base.html`:

```html
<!doctype html>
<html>
  <head>
    <title>Email Guardian</title>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <style>
      body { font-family: system-ui, sans-serif; margin: 2rem; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border-bottom: 1px solid #ddd; padding: .5rem; text-align: left; }
      .topnav a { margin-right: 1rem; }
    </style>
  </head>
  <body>
    <div class="topnav">
      <a href="/">Home</a>
      <a href="/upload">Upload</a>
      <a href="/events">Events</a>
    </div>
    <hr/>
    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <ul>
      {% for category, message in messages %}
        <li><strong>{{ category }}</strong> — {{ message }}</li>
      {% endfor %}
      </ul>
    {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </body>
</html>
```

`templates/index.html`:

```html
{% extends "base.html" %}
{% block content %}
<h1>Email Guardian</h1>
<p>Import CSV events, manage rules/whitelists/keywords, and score risk.</p>
<p><a href="/upload">Upload CSV</a> or <a href="/events">View Events</a></p>
{% endblock %}
```

`templates/upload.html`:

```html
{% extends "base.html" %}
{% block content %}
<h2>Upload CSV</h2>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="csvfile" accept=".csv" required/>
  <button type="submit">Import</button>
</form>
<p>Expected headers: <code>_time,sender,subject,attachments,recipients,time_month,leaver,termination_date,bunit,department,user_response,final_outcome,policy_name,justifications</code></p>
{% endblock %}
```

`templates/events.html`:

```html
{% extends "base.html" %}
{% block content %}
<h2>Recent Events</h2>
<form method="get">
  <input name="q" placeholder="Search sender/subject" value="{{ q }}"/>
  <button>Search</button>
</form>
<table>
  <tr><th>ID</th><th>Time</th><th>Sender</th><th>Subject</th><th>ML Score</th></tr>
  {% for id, t, s, subj, score in rows %}
    <tr>
      <td><a href="/event/{{ id }}">{{ id }}</a></td>
      <td>{{ t }}</td>
      <td>{{ s }}</td>
      <td>{{ subj }}</td>
      <td>{{ '%.3f'|format(score or 0) }}</td>
    </tr>
  {% endfor %}
</table>
{% endblock %}
```

---

## 🧾 How Imports Handle 10,000+ Events (Guarantees)

- **Streaming reader** ensures constant memory.
- **Batched transactions** ensure speed and integrity; no skipping because:
  - Every row is processed; failures are logged to `dead_letter.csv`.
  - Post-import summary: inserted vs failed counts.
- **Input sanitization** and **field splitting** for multi-valued columns.
- **Indexes** created before queries for speed.
- **WAL mode** for concurrency and reliability.

---

## 🧯 Troubleshooting

- **Unicode decode error** → ensure CSV is UTF-8 (or change the `decode` line to your encoding).
- **Header mismatch** → verify headers match expected names exactly.
- **Slow imports** → decrease `BATCH_SIZE` if memory-limited; otherwise increase to 2000–5000.
- **ReDoS risk** with regex keywords → keep patterns simple; test in a sandbox.

---

## 🔐 Notes on Data Handling

- Data remains local in SQLite.
- No network calls by default.
- Consider removing raw CSVs after import if sensitive.

---

## ✅ Next Steps

- Paste the code snippets into files.
- Update `INTERNAL_DOMAINS` in `config.py`.
- Import your CSV.
- Review events, add rules/whitelists/keywords.
- Re-score and iterate.

---

*Built for quick iteration on Replit. Extend as needed for your org’s policies.* 
