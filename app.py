
from __future__ import annotations
import os, sqlite3, uuid, datetime as dt
from functools import wraps
from flask import Flask, g, redirect, render_template, request, session, url_for, abort, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
DB_PATH = os.environ.get('BPLO_DB', 'bplo_queue.db')

# ----------------------- DB Helpers -----------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

SCHEMA_SQL = '''
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','staff','office','display')),
    office_id INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (office_id) REFERENCES offices(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS offices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    is_signatory INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT UNIQUE NOT NULL,
    number INTEGER NOT NULL,
    stage TEXT NOT NULL CHECK(stage IN ('verification','process','released')),
    status TEXT NOT NULL CHECK(status IN ('waiting','serving','hold','done')),
    priority TEXT NOT NULL CHECK(priority IN ('regular','priority')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    current_office_id INTEGER,
    paid INTEGER NOT NULL DEFAULT 0,
    ready_for_release INTEGER NOT NULL DEFAULT 0,
    released_at TEXT,
    FOREIGN KEY (current_office_id) REFERENCES offices(id)
);

CREATE TABLE IF NOT EXISTS ticket_office_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    office_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','approved','hold')) DEFAULT 'pending',
    note TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(ticket_id, office_id),
    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
    FOREIGN KEY (office_id) REFERENCES offices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
'''

def init_db():
    db = get_db()
    db.executescript(SCHEMA_SQL)
    # Seed offices
    default_offices = ['City Health Office', 'Engineering Office', 'Environment', 'Zoning', 'Treasury']
    cur = db.execute('SELECT COUNT(*) AS c FROM offices')
    if cur.fetchone()['c'] == 0:
        for name in default_offices:
            db.execute('INSERT INTO offices (name, is_signatory) VALUES (?,1)', (name,))
        db.commit()
    # Seed admin
    cur = db.execute('SELECT COUNT(*) AS c FROM users')
    if cur.fetchone()['c'] == 0:
        db.execute('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)',
                   ('admin', generate_password_hash('admin123'), 'admin'))
        db.commit()

@app.before_first_request
def _startup():
    init_db()

# ----------------------- Auth -----------------------
def login_required(role: str|None=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login', next=request.path))
            if role and session.get('role') not in (role, 'admin'):
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = get_db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.update({'user_id': user['id'], 'username': user['username'], 'role': user['role'], 'office_id': user['office_id']})
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------------------- Utils -----------------------
def next_ticket_number(stage: str) -> int:
    db = get_db()
    today = dt.date.today().isoformat()
    cur = db.execute("SELECT COUNT(*) AS c FROM tickets WHERE stage=? AND date(created_at)=?", (stage, today))
    return cur.fetchone()['c'] + 1

# ----------------------- Dashboard -----------------------
@app.route('/')
@login_required()
def dashboard():
    role = session.get('role')
    if role == 'admin':
        db = get_db()
        stats = {}
        stats['verification_waiting'] = db.execute("SELECT COUNT(*) c FROM tickets WHERE stage='verification' AND status IN ('waiting','hold')").fetchone()['c']
        stats['process_waiting'] = db.execute("SELECT COUNT(*) c FROM tickets WHERE stage='process' AND status IN ('waiting','hold')").fetchone()['c']
        stats['released_today'] = db.execute("SELECT COUNT(*) c FROM tickets WHERE stage='released' AND date(released_at)=date('now')").fetchone()['c']
        return render_template('admin_dashboard.html', stats=stats, user=session)
    elif role == 'staff':
        return redirect(url_for('staff_verification'))
    elif role == 'office':
        return redirect(url_for('office_queue'))
    else:
        return redirect(url_for('display_board'))

# ----------------------- Admin: Users -----------------------
@app.route('/admin/users', methods=['GET','POST'])
@login_required('admin')
def admin_users():
    db = get_db()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form['role']
        office_id = request.form.get('office_id') or None
        try:
            db.execute('INSERT INTO users (username, password_hash, role, office_id) VALUES (?,?,?,?)',
                       (username, generate_password_hash(password), role, office_id))
            db.commit()
            flash('User created', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
    users = db.execute('''SELECT u.*, o.name as office_name FROM users u
                          LEFT JOIN offices o ON u.office_id=o.id
                          ORDER BY u.id DESC''').fetchall()
    offices = db.execute('SELECT * FROM offices ORDER BY name').fetchall()
    return render_template('admin_users.html', users=users, offices=offices)

@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@login_required('admin')
def admin_delete_user(uid):
    db = get_db()
    if uid == session.get('user_id'):
        flash("You can't delete yourself.", 'warning')
    else:
        db.execute('DELETE FROM users WHERE id=?', (uid,))
        db.commit()
        flash('User deleted', 'info')
    return redirect(url_for('admin_users'))

# ----------------------- Admin: Offices -----------------------
@app.route('/admin/offices', methods=['GET','POST'])
@login_required('admin')
def admin_offices():
    db = get_db()
    if request.method == 'POST':
        name = request.form['name'].strip()
        is_signatory = 1 if request.form.get('is_signatory') == 'on' else 0
        try:
            db.execute('INSERT INTO offices (name, is_signatory) VALUES (?,?)', (name, is_signatory))
            db.commit()
            flash('Office added', 'success')
        except sqlite3.IntegrityError:
            flash('Office already exists', 'danger')
    offices = db.execute('SELECT * FROM offices ORDER BY name').fetchall()
    return render_template('admin_offices.html', offices=offices)

@app.route('/admin/offices/<int:oid>/delete', methods=['POST'])
@login_required('admin')
def admin_delete_office(oid):
    db = get_db()
    db.execute('DELETE FROM offices WHERE id=?', (oid,))
    db.commit()
    flash('Office deleted', 'info')
    return redirect(url_for('admin_offices'))

# ----------------------- Ticket: Creation -----------------------
@app.route('/ticket/new', methods=['POST'])
@login_required('staff')
def new_ticket():
    stage = request.form.get('stage', 'verification')
    priority = request.form.get('priority', 'regular')
    number = next_ticket_number(stage)
    public_id = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO tickets (public_id, number, stage, status, priority) VALUES (?,?,?,?,?)",
        (public_id, number, stage, 'waiting', priority)
    )
    ticket_id = db.execute('SELECT last_insert_rowid() as id').fetchone()['id']
    offices = db.execute('SELECT * FROM offices WHERE is_signatory=1').fetchall()
    for o in offices:
        db.execute('INSERT INTO ticket_office_status (ticket_id, office_id, status) VALUES (?,?,"pending")', (ticket_id, o['id']))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)',
               (ticket_id, session['user_id'], 'create', f'stage={stage}; priority={priority}; number={number}'))
    db.commit()
    flash(f'Created ticket #{number} for {stage}', 'success')
    return redirect(url_for('staff_verification' if stage=='verification' else 'staff_process'))

# ----------------------- Staff: Verification -----------------------
@app.route('/staff/verification')
@login_required('staff')
def staff_verification():
    db = get_db()
    waiting = db.execute(
        "SELECT * FROM tickets WHERE stage='verification' AND status IN ('waiting','hold') ORDER BY CASE priority WHEN 'priority' THEN 0 ELSE 1 END, id ASC"
    ).fetchall()
    serving = db.execute(
        "SELECT * FROM tickets WHERE stage='verification' AND status='serving' ORDER BY updated_at DESC"
    ).fetchall()
    return render_template('staff_verification.html', waiting=waiting, serving=serving)

@app.route('/staff/verification/call_next', methods=['POST'])
@login_required('staff')
def verif_call_next():
    db = get_db()
    row = db.execute(
        "SELECT * FROM tickets WHERE stage='verification' AND status IN ('waiting','hold') ORDER BY CASE priority WHEN 'priority' THEN 0 ELSE 1 END, id ASC LIMIT 1"
    ).fetchone()
    if not row:
        flash('No tickets waiting.', 'info')
        return redirect(url_for('staff_verification'))
    db.execute("UPDATE tickets SET status='serving', updated_at=datetime('now') WHERE id=?", (row['id'],))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (row['id'], session['user_id'], 'call', 'verification'))
    db.commit()
    return redirect(url_for('staff_verification'))

@app.route('/staff/verification/hold/<int:tid>', methods=['POST'])
@login_required('staff')
def verif_hold(tid):
    note = request.form.get('note','')
    db = get_db()
    db.execute("UPDATE tickets SET status='hold', updated_at=datetime('now') WHERE id=?", (tid,))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'hold', note))
    db.commit()
    return redirect(url_for('staff_verification'))

@app.route('/staff/verification/approve/<int:tid>', methods=['POST'])
@login_required('staff')
def verif_approve(tid):
    db = get_db()
    office = db.execute('''
        SELECT o.* FROM ticket_office_status t
        JOIN offices o ON o.id=t.office_id
        WHERE t.ticket_id=? AND t.status='pending'
        ORDER BY o.id ASC LIMIT 1
    ''', (tid,)).fetchone()
    if office:
        db.execute('UPDATE tickets SET current_office_id=?, status="waiting", updated_at=datetime("now") WHERE id=?', (office['id'], tid))
    else:
        db.execute('UPDATE tickets SET stage="process", status="waiting", current_office_id=NULL, updated_at=datetime("now") WHERE id=?', (tid,))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'verify_approved', 'to signatories'))
    db.commit()
    return redirect(url_for('staff_verification'))

# ----------------------- Office: Signatory Queue -----------------------
@app.route('/office/queue', methods=['GET','POST'])
@login_required('office')
def office_queue():
    db = get_db()
    office_id = session.get('office_id')
    if not office_id:
        flash('Your user is not linked to an office. Ask admin to update.', 'warning')
    tickets = db.execute('''
        SELECT t.*, tos.status as ostatus, tos.note as onote, o.name as office_name
        FROM tickets t
        JOIN ticket_office_status tos ON tos.ticket_id=t.id
        JOIN offices o ON o.id=tos.office_id
        WHERE tos.office_id=? AND t.stage='verification' AND tos.status IN ('pending','hold')
        ORDER BY CASE t.priority WHEN 'priority' THEN 0 ELSE 1 END, t.id ASC
    ''', (office_id,)).fetchall()
    return render_template('office_queue.html', tickets=tickets)

@app.route('/office/queue/<int:tid>/action', methods=['POST'])
@login_required('office')
def office_action(tid):
    db = get_db()
    office_id = session.get('office_id')
    action = request.form.get('action')
    note = request.form.get('note','')
    if action == 'approve':
        db.execute('UPDATE ticket_office_status SET status="approved", note=?, updated_at=datetime("now") WHERE ticket_id=? AND office_id=?', (note, tid, office_id))
        next_off = db.execute('SELECT office_id FROM ticket_office_status WHERE ticket_id=? AND status="pending" ORDER BY office_id ASC LIMIT 1', (tid,)).fetchone()
        if next_off:
            db.execute('UPDATE tickets SET current_office_id=?, status="waiting", updated_at=datetime("now") WHERE id=?', (next_off['office_id'], tid))
        else:
            db.execute('UPDATE tickets SET stage="process", status="waiting", current_office_id=NULL, updated_at=datetime("now") WHERE id=?', (tid,))
        db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'office_approved', f'office_id={office_id}'))
    elif action == 'hold':
        db.execute('UPDATE ticket_office_status SET status="hold", note=?, updated_at=datetime("now") WHERE ticket_id=? AND office_id=?', (note, tid, office_id))
        db.execute('UPDATE tickets SET status="hold", current_office_id=?, updated_at=datetime("now") WHERE id=?', (office_id, tid))
        db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'office_hold', f'office_id={office_id}; {note}'))
    else:
        flash('Unknown action', 'danger')
    db.commit()
    return redirect(url_for('office_queue'))

# ----------------------- Staff: Process Proper -----------------------
@app.route('/staff/process')
@login_required('staff')
def staff_process():
    db = get_db()
    waiting = db.execute("SELECT * FROM tickets WHERE stage='process' AND status IN ('waiting','hold') ORDER BY CASE priority WHEN 'priority' THEN 0 ELSE 1 END, id ASC").fetchall()
    serving = db.execute("SELECT * FROM tickets WHERE stage='process' AND status='serving' ORDER BY updated_at DESC").fetchall()
    return render_template('staff_process.html', waiting=waiting, serving=serving)

@app.route('/staff/process/call_next', methods=['POST'])
@login_required('staff')
def process_call_next():
    db = get_db()
    row = db.execute("SELECT * FROM tickets WHERE stage='process' AND status IN ('waiting','hold') ORDER BY CASE priority WHEN 'priority' THEN 0 ELSE 1 END, id ASC LIMIT 1").fetchone()
    if not row:
        flash('No tickets waiting.', 'info')
        return redirect(url_for('staff_process'))
    db.execute("UPDATE tickets SET status='serving', updated_at=datetime('now') WHERE id=?", (row['id'],))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (row['id'], session['user_id'], 'call', 'process'))
    db.commit()
    return redirect(url_for('staff_process'))

@app.route('/staff/process/hold/<int:tid>', methods=['POST'])
@login_required('staff')
def process_hold(tid):
    note = request.form.get('note','')
    db = get_db()
    db.execute("UPDATE tickets SET status='hold', updated_at=datetime('now') WHERE id=?", (tid,))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'hold', note))
    db.commit()
    return redirect(url_for('staff_process'))

@app.route('/staff/process/mark_paid/<int:tid>', methods=['POST'])
@login_required('staff')
def process_paid(tid):
    db = get_db()
    db.execute('UPDATE tickets SET paid=1, updated_at=datetime("now") WHERE id=?', (tid,))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'paid', '1'))
    db.commit()
    return redirect(url_for('staff_process'))

@app.route('/staff/process/ready_release/<int:tid>', methods=['POST'])
@login_required('staff')
def process_ready_release(tid):
    db = get_db()
    db.execute('UPDATE tickets SET ready_for_release=1, status="done", updated_at=datetime("now") WHERE id=?', (tid,))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'ready_release', '1'))
    db.commit()
    return redirect(url_for('staff_process'))

@app.route('/staff/process/release/<int:tid>', methods=['POST'])
@login_required('staff')
def process_release(tid):
    db = get_db()
    db.execute('UPDATE tickets SET stage="released", released_at=datetime("now"), updated_at=datetime("now") WHERE id=?', (tid,))
    db.execute('INSERT INTO events (ticket_id, user_id, action, details) VALUES (?,?,?,?)', (tid, session['user_id'], 'released', '1'))
    db.commit()
    return redirect(url_for('staff_process'))

# ----------------------- Public Tracking & QR -----------------------
@app.route('/track/<public_id>')
def public_track(public_id):
    db = get_db()
    t = db.execute('SELECT * FROM tickets WHERE public_id=?', (public_id,)).fetchone()
    if not t:
        abort(404)
    offices = db.execute('''
        SELECT o.name, tos.status, tos.note, tos.updated_at
        FROM ticket_office_status tos JOIN offices o ON o.id=tos.office_id
        WHERE tos.ticket_id=? ORDER BY o.id
    ''', (t['id'],)).fetchall()
    events = db.execute('''
        SELECT e.*, u.username FROM events e LEFT JOIN users u ON u.id=e.user_id
        WHERE e.ticket_id=? ORDER BY e.id DESC LIMIT 50
    ''', (t['id'],)).fetchall()
    return render_template('public_track.html', t=t, offices=offices, events=events)

@app.route('/qr/<public_id>.png')
def qr_code(public_id):
    track_url = request.url_root.strip('/') + url_for('public_track', public_id=public_id)
    img = qrcode.make(track_url)
    path = os.path.join('tmp_qr.png')
    img.save(path)
    return send_file(path, mimetype='image/png')

# ----------------------- Display Board -----------------------
@app.route('/display')
def display_board():
    db = get_db()
    ver = db.execute("SELECT number, status, priority, updated_at FROM tickets WHERE stage='verification' AND status='serving' ORDER BY updated_at DESC LIMIT 5").fetchall()
    proc = db.execute("SELECT number, status, priority, updated_at FROM tickets WHERE stage='process' AND status='serving' ORDER BY updated_at DESC LIMIT 5").fetchall()
    return render_template('display.html', ver=ver, proc=proc)

# ----------------------- Staff quick create page -----------------------
@app.route('/staff')
@login_required('staff')
def staff_home():
    return redirect(url_for('staff_verification'))

if __name__ == '__main__':
    app.run(debug=True)
