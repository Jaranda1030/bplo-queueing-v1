from flask import Flask, render_template, request, redirect, url_for, abort, flash
import sqlite3, os
from datetime import datetime
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin

DB_PATH = "queue.db"
QR_DIR = os.path.join("static", "qrcodes")
LOGO_DIR = os.path.join("static", "uploads", "logos")
SLIDE_DIR = os.path.join("static", "uploads", "slides")
for d in (QR_DIR, LOGO_DIR, SLIDE_DIR):
    os.makedirs(d, exist_ok=True)

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
PREFIX_VER = os.getenv("PREFIX_VER", "V")
PREFIX_PROC = os.getenv("PREFIX_PROC", "P")
DEFAULT_OFFICES = ["City Health", "Engineering", "Environment", "Zoning", "Treasury"]

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET","devsecret")

login_manager = LoginManager(app)
login_manager.login_view = "login"

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.role = row["role"]
        self.office_id = row["office_id"]

@login_manager.user_loader
def load_user(user_id):
    con = db(); c = con.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    r = c.fetchone(); con.close()
    return User(r) if r else None

def init_db():
    con = db(); c = con.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT, office_id INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS offices (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)")
    c.execute("CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, queue_type TEXT, queue_number TEXT, tracking_number TEXT, service_type TEXT, priority INTEGER DEFAULT 0, status TEXT, hold_reason TEXT, called_by TEXT, station_label TEXT, window_note TEXT, created_at TEXT, called_at TEXT, served_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS steps (id INTEGER PRIMARY KEY AUTOINCREMENT, tracking_number TEXT, step_order INTEGER, office_id INTEGER, office_name TEXT, status TEXT, note TEXT, updated_at TEXT)")
    con.commit()
    c.execute("SELECT COUNT(*) FROM offices"); n = c.fetchone()[0]
    if n == 0:
        for name in DEFAULT_OFFICES:
            c.execute("INSERT INTO offices (name) VALUES (?)", (name,))
        con.commit()
    c.execute("SELECT COUNT(*) FROM users"); u = c.fetchone()[0]
    if u == 0:
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD)))
        con.commit()
    con.close()

init_db()

def create_qr(tracking, host_url):
    path = os.path.join(QR_DIR, f"{tracking}.png")
    url = host_url.rstrip('/') + url_for('track', tracking=tracking)
    qrcode.make(url).save(path)
    return path

def today_count(queue_type):
    con = db(); c = con.cursor()
    c.execute("SELECT COUNT(*) FROM tickets WHERE queue_type=? AND date(created_at)=date('now','localtime')", (queue_type,))
    n = c.fetchone()[0] or 0
    con.close()
    return n

def new_queue_number(queue_type):
    n = today_count(queue_type) + 1
    prefix = PREFIX_VER if queue_type == "verification" else PREFIX_PROC
    return f"{prefix}-{n:03d}"

def new_tracking_number(queue_type):
    datepart = datetime.now().strftime("%Y%m%d")
    n = today_count(queue_type) + 1
    base = "VER" if queue_type == "verification" else "PROC"
    return f"{base}-{datepart}-{n:03d}"

def build_verification_steps(tracking):
    con = db(); c = con.cursor()
    c.execute("SELECT id,name FROM offices ORDER BY id")
    offices = c.fetchall()
    now = datetime.now().isoformat(" ", "seconds")
    for i, o in enumerate(offices, start=1):
        c.execute("INSERT INTO steps (tracking_number, step_order, office_id, office_name, status, updated_at) VALUES (?,?,?,?, 'pending', ?)", (tracking, i, o["id"], o["name"], now))
    con.commit(); con.close()

def user_in_roles(*roles):
    return current_user.is_authenticated and (current_user.role in roles or current_user.role == "admin")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        con = db(); c = con.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        r = c.fetchone(); con.close()
        if r and check_password_hash(r["password_hash"], password):
            login_user(User(r))
            return redirect(url_for("home"))
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return render_template("home.html")

@app.route("/admin/offices", methods=["GET","POST"])
@login_required
def admin_offices():
    if not user_in_roles("admin"): abort(403)
    con = db(); c = con.cursor(); msg = ""
    if request.method == "POST":
        name = request.form.get("name","").strip()
        if name:
            try:
                c.execute("INSERT INTO offices (name) VALUES (?)", (name,)); con.commit(); msg = "Office added."
            except sqlite3.IntegrityError:
                msg = "Office already exists."
    c.execute("SELECT * FROM offices ORDER BY id"); offices = c.fetchall()
    con.close()
    return render_template("admin_offices.html", offices=offices, msg=msg)

@app.route("/admin/users", methods=["GET","POST"])
@login_required
def admin_users():
    if not user_in_roles("admin"): abort(403)
    con = db(); c = con.cursor(); msg = ""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        role = request.form.get("role","verification_staff")
        office_id = request.form.get("office_id") or None
        if office_id: office_id = int(office_id)
        if username and password:
            try:
                c.execute("INSERT INTO users (username, password_hash, role, office_id) VALUES (?, ?, ?, ?)", (username, generate_password_hash(password), role, office_id))
                con.commit(); msg = "User created."
            except sqlite3.IntegrityError:
                msg = "Username already exists."
    c.execute("SELECT * FROM offices ORDER BY name"); offices = c.fetchall()
    c.execute("SELECT u.*, o.name as office_name FROM users u LEFT JOIN offices o ON u.office_id=o.id ORDER BY u.id DESC")
    users = c.fetchall(); con.close()
    return render_template("admin_users.html", offices=offices, users=users, msg=msg)

@app.route("/admin/reset", methods=["GET","POST"])
@login_required
def admin_reset():
    if not user_in_roles("admin"): abort(403)
    msg = ""
    if request.method == "POST":
        con = db(); c = con.cursor()
        act = request.form.get("action")
        if act == "reset_today":
            c.execute("DELETE FROM tickets WHERE date(created_at)=date('now','localtime')")
            c.execute("DELETE FROM steps WHERE tracking_number NOT IN (SELECT tracking_number FROM tickets)")
            con.commit(); msg = "Today's records cleared."
        elif act == "delete_all":
            c.execute("DELETE FROM tickets"); c.execute("DELETE FROM steps"); con.commit(); msg = "All records cleared."
        con.close()
    return render_template("admin_reset.html", msg=msg)

@app.route("/kiosk")
def kiosk():
    return render_template("kiosk.html")

@app.route("/get_ticket", methods=["POST"])
def get_ticket():
    queue_type = request.form.get("queue_type","verification")
    service = request.form.get("service","Business Permit")
    priority = 1 if request.form.get("priority") == "on" else 0
    qnum = new_queue_number(queue_type)
    tnum = new_tracking_number(queue_type)
    now = datetime.now().isoformat(" ", "seconds")
    con = db(); c = con.cursor()
    c.execute("INSERT INTO tickets (queue_type,queue_number,tracking_number,service_type,priority,status,created_at) VALUES (?,?,?,?,?, 'waiting', ?)", (queue_type,qnum,tnum,service,priority,now))
    con.commit()
    if queue_type == "verification":
        build_verification_steps(tnum)
    con.close()
    create_qr(tnum, request.host_url)
    return redirect(url_for("ticket", tracking=tnum))

@app.route("/ticket/<tracking>")
def ticket(tracking):
    con = db(); c = con.cursor()
    c.execute("SELECT * FROM tickets WHERE tracking_number=?", (tracking,)); t=c.fetchone(); con.close()
    if not t: abort(404)
    qr_url = url_for('static', filename=f"qrcodes/{tracking}.png")
    return render_template("ticket.html", ticket=t, qr_url=qr_url)

from flask import url_for
@app.route("/track/<tracking>")
def track(tracking):
    con = db(); c = con.cursor()
    c.execute("SELECT * FROM tickets WHERE tracking_number=? ORDER BY id DESC LIMIT 1", (tracking,)); t=c.fetchone()
    if not t: abort(404)
    c.execute("SELECT * FROM steps WHERE tracking_number=? ORDER BY step_order", (tracking,)); steps = c.fetchall()
    con.close()
    return render_template("track.html", ticket=t, steps=steps)

# Verification staff
@app.route("/staff/verification")
@login_required
def staff_verification():
    if not user_in_roles("verification_staff"): abort(403)
    con=db(); c=con.cursor()
    c.execute("SELECT * FROM tickets WHERE queue_type='verification' AND status='called' ORDER BY called_at DESC LIMIT 10"); current=c.fetchall()
    c.execute("SELECT * FROM tickets WHERE queue_type='verification' AND status='waiting' ORDER BY priority DESC, id ASC LIMIT 50"); waiting=c.fetchall()
    c.execute("SELECT * FROM tickets WHERE queue_type='verification' AND status='on_hold' ORDER BY id ASC LIMIT 50"); onhold=c.fetchall()
    con.close()
    return render_template("staff_verification.html", current=current, waiting=waiting, onhold=onhold)

@app.route("/verification/take_next", methods=["POST"])
@login_required
def verification_take_next():
    if not user_in_roles("verification_staff"): abort(403)
    station = request.form.get("station","V1")
    con=db(); c=con.cursor()
    c.execute("BEGIN IMMEDIATE")
    c.execute("SELECT id FROM tickets WHERE queue_type='verification' AND status='waiting' ORDER BY priority DESC, id ASC LIMIT 1")
    row=c.fetchone()
    if row:
        now=datetime.now().isoformat(" ","seconds")
        c.execute("UPDATE tickets SET status='called', called_at=?, called_by=?, station_label=? WHERE id=? AND status='waiting'", (now, current_user.username, station, row["id"]))
    con.commit(); con.close()
    return redirect(url_for("staff_verification"))

@app.route("/verification/forward/<tracking>", methods=["POST"])
@login_required
def verification_forward(tracking):
    if not user_in_roles("verification_staff"): abort(403)
    now = datetime.now().isoformat(" ","seconds")
    con=db(); c=con.cursor()
    c.execute("UPDATE tickets SET status='completed', served_at=? WHERE tracking_number=? AND queue_type='verification'", (now, tracking))
    c.execute("SELECT service_type, priority FROM tickets WHERE tracking_number=? ORDER BY id ASC LIMIT 1", (tracking,))
    base = c.fetchone() or {"service_type":"Business Permit","priority":0}
    qnum = new_queue_number("process")
    proc_tracking = tracking.replace("VER","PROC") if tracking.startswith("VER") else f"PROC-{tracking}"
    service_type = base["service_type"] if isinstance(base, sqlite3.Row) else base["service_type"]
    priority = base["priority"] if isinstance(base, sqlite3.Row) else base["priority"]
    c.execute("INSERT INTO tickets (queue_type,queue_number,tracking_number,service_type,priority,status,created_at) VALUES ('process',?,?,?,?, 'waiting', ?)", (qnum, proc_tracking, service_type, priority, now))
    con.commit(); con.close()
    create_qr(proc_tracking, request.host_url)
    return redirect(url_for("staff_verification"))

@app.route("/verification/hold/<tracking>", methods=["POST"])
@login_required
def verification_hold(tracking):
    if not user_in_roles("verification_staff"): abort(403)
    reason = request.form.get("reason","On hold").strip() or "On hold"
    con=db(); c=con.cursor()
    c.execute("UPDATE tickets SET status='on_hold', hold_reason=? WHERE tracking_number=?", (reason, tracking))
    con.commit(); con.close()
    return redirect(url_for("staff_verification"))

@app.route("/verification/resume/<tracking>", methods=["POST"])
@login_required
def verification_resume(tracking):
    if not user_in_roles("verification_staff"): abort(403)
    con=db(); c=con.cursor()
    c.execute("UPDATE tickets SET status='waiting' WHERE tracking_number=?", (tracking,))
    con.commit(); con.close()
    return redirect(url_for("staff_verification"))

# Office staff
@app.route("/office")
@login_required
def office_list():
    if not user_in_roles("office_staff"): abort(403)
    con=db(); c=con.cursor()
    c.execute("SELECT t.*, s.step_order, s.status as step_status, s.note, s.office_name FROM steps s JOIN tickets t ON t.tracking_number = s.tracking_number WHERE s.office_id=? AND t.queue_type='verification' AND t.status IN ('waiting','called','on_hold') ORDER BY t.priority DESC, t.id ASC", (current_user.office_id,))
    items = c.fetchall(); con.close()
    return render_template("office.html", items=items)

@app.route("/office/update/<tracking>", methods=["POST"])
@login_required
def office_update(tracking):
    if not user_in_roles("office_staff"): abort(403)
    action = request.form.get("action")
    note = request.form.get("note","").strip()
    now = datetime.now().isoformat(" ","seconds")
    con=db(); c=con.cursor()
    c.execute("SELECT * FROM steps WHERE tracking_number=? AND office_id=?", (tracking, current_user.office_id))
    step = c.fetchone()
    if not step: con.close(); abort(404)
    if action == "note":
        c.execute("UPDATE steps SET note=?, updated_at=? WHERE id=?", (note, now, step["id"]))
    elif action == "hold":
        reason = note or "On hold"
        c.execute("UPDATE steps SET status='on_hold', note=?, updated_at=? WHERE id=?", (reason, now, step["id"]))
        c.execute("UPDATE tickets SET status='on_hold', hold_reason=? WHERE tracking_number=?", (reason, tracking))
    elif action == "done":
        c.execute("UPDATE steps SET status='done', updated_at=? WHERE id=?", (now, step["id"]))
        c.execute("SELECT * FROM steps WHERE tracking_number=? AND status IN ('pending','on_hold') ORDER BY step_order LIMIT 1", (tracking,))
        nxt = c.fetchone()
        if nxt:
            c.execute("UPDATE steps SET status='in_progress', updated_at=? WHERE id=?", (now, nxt["id"]))
        else:
            c.execute("UPDATE tickets SET status='completed', served_at=? WHERE tracking_number=? AND queue_type='verification'", (now, tracking))
    con.commit(); con.close()
    return redirect(url_for("office_list"))

@app.route("/office/resume_ticket/<tracking>", methods=["POST"])
@login_required
def office_resume_ticket(tracking):
    if not user_in_roles("office_staff"): abort(403)
    con=db(); c=con.cursor()
    c.execute("UPDATE tickets SET status='waiting' WHERE tracking_number=?", (tracking,))
    c.execute("UPDATE steps SET status='pending' WHERE tracking_number=? AND office_id=?", (tracking, current_user.office_id))
    con.commit(); con.close()
    return redirect(url_for("office_list"))

# Process staff
@app.route("/staff/process")
@login_required
def staff_process():
    if not user_in_roles("process_staff"): abort(403)
    con=db(); c=con.cursor()
    c.execute("SELECT * FROM tickets WHERE queue_type='process' AND status='called' ORDER BY called_at DESC LIMIT 10"); current=c.fetchall()
    c.execute("SELECT * FROM tickets WHERE queue_type='process' AND status='waiting' ORDER BY priority DESC, id ASC LIMIT 50"); waiting=c.fetchall()
    c.execute("SELECT * FROM tickets WHERE queue_type='process' AND status='on_hold' ORDER BY id ASC LIMIT 50"); onhold=c.fetchall()
    con.close()
    return render_template("staff_process.html", current=current, waiting=waiting, onhold=onhold)

@app.route("/process/take_next", methods=["POST"])
@login_required
def process_take_next():
    if not user_in_roles("process_staff"): abort(403)
    station = request.form.get("station","P1")
    con=db(); c=con.cursor()
    c.execute("BEGIN IMMEDIATE")
    c.execute("SELECT id FROM tickets WHERE queue_type='process' AND status='waiting' ORDER BY priority DESC, id ASC LIMIT 1")
    row=c.fetchone()
    if row:
        now=datetime.now().isoformat(" ","seconds")
        c.execute("UPDATE tickets SET status='called', called_at=?, called_by=?, station_label=? WHERE id=? AND status='waiting'", (now, current_user.username, station, row["id"]))
    con.commit(); con.close()
    return redirect(url_for("staff_process"))

@app.route("/process/hold/<tracking>", methods=["POST"])
@login_required
def process_hold(tracking):
    if not user_in_roles("process_staff"): abort(403)
    reason = request.form.get("reason","On hold").strip() or "On hold"
    con=db(); c=con.cursor()
    c.execute("UPDATE tickets SET status='on_hold', hold_reason=? WHERE tracking_number=?", (reason, tracking))
    con.commit(); con.close()
    return redirect(url_for("staff_process"))

@app.route("/process/advance/<tracking>", methods=["POST"])
@login_required
def process_advance(tracking):
    if not user_in_roles("process_staff"): abort(403)
    con=db(); c=con.cursor()
    c.execute("SELECT hold_reason,status FROM tickets WHERE tracking_number=?", (tracking,))
    row=c.fetchone()
    now=datetime.now().isoformat(" ","seconds")
    if row:
        phase = (row["hold_reason"] or "Assessment").strip()
        nxt = "Payment" if phase=="Assessment" else ("Release" if phase=="Payment" else "Completed")
        if nxt=="Completed":
            c.execute("UPDATE tickets SET status='completed', served_at=? WHERE tracking_number=?", (now, tracking))
        else:
            c.execute("UPDATE tickets SET hold_reason=? WHERE tracking_number=?", (nxt, tracking))
    con.commit(); con.close()
    return redirect(url_for("staff_process"))

@app.route("/process/resume/<tracking>", methods=["POST"])
@login_required
def process_resume(tracking):
    if not user_in_roles("process_staff"): abort(403)
    con=db(); c=con.cursor()
    c.execute("UPDATE tickets SET status='waiting' WHERE tracking_number=?", (tracking,))
    con.commit(); con.close()
    return redirect(url_for("staff_process"))

# Public display
@app.route("/display")
def display():
    con=db(); c=con.cursor()
    c.execute("SELECT * FROM tickets WHERE queue_type='verification' AND status='called' ORDER BY called_at DESC LIMIT 10"); ver_current = c.fetchall()
    c.execute("SELECT * FROM tickets WHERE queue_type='verification' AND status='waiting' ORDER BY priority DESC, id ASC LIMIT 10"); ver_next = c.fetchall()
    c.execute("SELECT * FROM tickets WHERE queue_type='process' AND status='called' ORDER BY called_at DESC LIMIT 10"); proc_curr = c.fetchall()
    c.execute("SELECT * FROM tickets WHERE queue_type='process' AND status='waiting' ORDER BY priority DESC, id ASC LIMIT 10"); proc_next = c.fetchall()
    con.close()
    return render_template("display.html", ver_current=ver_current, ver_next=ver_next, proc_curr=proc_curr, proc_next=proc_next)

# Seed demo users
@app.route("/admin/seed_demo")
@login_required
def seed_demo():
    if not user_in_roles("admin"): abort(403)
    con=db(); c=con.cursor()
    c.execute("SELECT id FROM offices ORDER BY id LIMIT 1"); oi=c.fetchone()
    users = [("verif1","verif1","verification_staff",None), ("proc1","proc1","process_staff",None), ("display","display","display",None)]
    if oi: users.append(("office1","office1","office_staff",oi["id"]))
    for u,p,r,oid in users:
        try:
            c.execute("INSERT INTO users (username,password_hash,role,office_id) VALUES (?,?,?,?)", (u, generate_password_hash(p), r, oid))
        except sqlite3.IntegrityError:
            pass
    con.commit(); con.close()
    return "Seeded: verif1/verif1, proc1/proc1, display/display, office1/office1"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
