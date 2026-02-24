

from flask import Flask, render_template, request, redirect, session, send_file, flash, url_for, jsonify
import sqlite3, io, csv, datetime,pandas
from werkzeug.security import generate_password_hash, check_password_hash,pandas

app = Flask(__name__)
app.secret_key = "leave_planner_secret_2025"
DB = "db.sqlite"

# --------- helpers ------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def safe_role(r):
    """
    Normalize role values coming from forms/CSV to the canonical
    roles used in the app: 'employee', 'admin', 'superadmin'.
    Accept many variants and fallback to 'employee'.
    """
    if not r:
        return "employee" #return the employee 
    r = r.strip().lower()
    if r in ("employee", "user", "staff"):
        return "employee"
    if r in ("admin", "administrator"):
        return "admin"
    if r in ("superadmin", "super", "superuser", "super_user", "super user"):
        return "superadmin"#super user return 
    return "employee"

# --- Db------data---------- _-----
def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        unique_id TEXT UNIQUE,
        username TEXT,
        password TEXT,
        role TEXT,
        department TEXT,
        rank TEXT,
        status TEXT DEFAULT 'Active'#active state 
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS leaves(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        department TEXT,
        from_date TEXT,
        to_date TEXT,
        reason TEXT,
        status TEXT DEFAULT 'Pending',
        applied_on TEXT,
        approved_by INTEGER,
        plan1_from TEXT,
        plan1_to TEXT,
        plan2_from TEXT,
        plan2_to TEXT
    )""")
    conn.commit()

    # seed default users if empty
    cur.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()["c"] == 0:
        # main superadmin
        cur.execute("INSERT INTO users(name,unique_id,username,password,role,department,rank,status) VALUES(?,?,?,?,?,?,?,?)",
                    ("Super Admin","SUPERADMIN","super",generate_password_hash("super123"),"superadmin","All","INSP/RO","Active"))
        # departmental admins
        depts = ["FIT","FFC","FCE","FC","HQ"]
        ranks = ["INSP/T", "INSP/C", "SI/RO", "SI/T", "SI/C", "INSP/GD", "SI/GD", "ASI/DM"]
        for i, d in enumerate(depts):
            uname = d.lower()+"_admin123"
            uid = d.upper()+"ADMIN"
            rank = ranks[i % len(ranks)]
            cur.execute("INSERT INTO users(name,unique_id,username,password,role,department,rank,status) VALUES(?,?,?,?,?,?,?,?)",
                        (f"{d} Admin", uid, uname, generate_password_hash(d.lower()+"123"), "admin", d, rank, "Active"))
        conn.commit()
    conn.close()

with app.app_context():
    init_db()

# --- migration (safe, idempotent) ---..........
def migrate_leaves_table():
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute("PRAGMA table_info('leaves')")
        cols = [r['name'] for r in cur.fetchall()]
    except Exception:
        cols = []
    # add plan columns only if missing
    extras = ["plan1_from","plan1_to","plan2_from","plan2_to"]
    for c in extras:
        if c not in cols:
            try:
                cur.execute(f"ALTER TABLE leaves ADD COLUMN {c} TEXT")
                conn.commit()
            except Exception:
                pass
    
    # Add rank and status columns if missing
    try:
        cur.execute("PRAGMA table_info('users')")
        cols = [r['name'] for r in cur.fetchall()]
        if 'rank' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN rank TEXT")
            conn.commit()
        if 'status' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'Active'")
            conn.commit()
    except Exception:
        pass
    
    conn.close()

try:
    migrate_leaves_table()
except Exception:
    pass

# --- routes ---

@app.route("/")
def welcome():
    # If already logged in, go to dashboard
    if "uid" in session:
        return redirect("/dashboard")
    # Otherwise show welcome page
    return render_template("welcome.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        uid = request.form.get("unique_id") or request.form.get("username")
        pwd = request.form.get("password")
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE unique_id=? OR username=?",(uid, uid))
        user = cur.fetchone(); conn.close()
        if user and check_password_hash(user["password"], pwd):
            if user["status"] != "Active":
                flash("Your account is inactive. Contact administrator.","danger")
                return render_template("login.html")
            # store canonical keys used across the app
            session.update({
                "uid": user["id"],
                "role": user["role"],
                "dept": user["department"],
                "name": user["name"],
                "rank": user["rank"]
            })
            return redirect("/dashboard")
        flash("Invalid credentials","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

@app.route("/dashboard")
def dashboard():
    if "uid" not in session:
        return redirect("/login")
    
    conn = get_db(); cur = conn.cursor()
    
    # Get statistics based on role
    stats = {}
    
    # Total users count
    if session.get("role") == "superadmin":
        cur.execute("SELECT COUNT(*) as count FROM users")
    else:
        cur.execute("SELECT COUNT(*) as count FROM users WHERE department=?", (session.get("dept"),))
    stats["total_users"] = cur.fetchone()["count"]
    
    # Leaves this month
    current_month = datetime.datetime.now().strftime("%Y-%m")
    if session.get("role") == "superadmin":
        cur.execute("SELECT COUNT(*) as count FROM leaves WHERE applied_on LIKE ?", (f"{current_month}%",))
    elif session.get("role") == "admin":
        cur.execute("SELECT COUNT(*) as count FROM leaves WHERE department=? AND applied_on LIKE ?", 
                   (session.get("dept"), f"{current_month}%"))
    else:
        cur.execute("SELECT COUNT(*) as count FROM leaves WHERE user_id=? AND applied_on LIKE ?", 
                   (session.get("uid"), f"{current_month}%"))
    stats["month_leaves"] = cur.fetchone()["count"]
    
    # Total leaves this year
    current_year = datetime.datetime.now().strftime("%Y")
    if session.get("role") == "superadmin":
        cur.execute("SELECT COUNT(*) as count FROM leaves WHERE applied_on LIKE ?", (f"{current_year}%",))
    elif session.get("role") == "admin":
        cur.execute("SELECT COUNT(*) as count FROM leaves WHERE department=? AND applied_on LIKE ?", 
                   (session.get("dept"), f"{current_year}%"))
    else:
        cur.execute("SELECT COUNT(*) as count FROM leaves WHERE user_id=? AND applied_on LIKE ?", 
                   (session.get("uid"), f"{current_year}%"))
    stats["year_leaves"] = cur.fetchone()["count"]
    
    conn.close()
    
    return render_template("dashboard.html", 
                         name=session.get("name"), 
                         role=session.get("role"), 
                         dept=session.get("dept"),
                         rank=session.get("rank"),
                         stats=stats)

@app.route("/upload_users", methods=["GET","POST"])
def upload_users():
    # only admin and superadmin can upload users
    if "uid" not in session or session.get("role") not in ("admin","superadmin"):
        flash("Not authorized","danger")
        return redirect("/dashboard")
    if request.method=="POST":
        f = request.files.get("file")
        if not f:
            flash("No file uploaded","danger"); return redirect("/upload_users")
        try:
            data = f.read().decode("utf-8").splitlines()
            reader = csv.DictReader(data)
            conn = get_db(); cur = conn.cursor()
            added = 0; skipped = 0
            for row in reader:
                name = (row.get("name") or "").strip()
                unique_id = (row.get("unique_id") or "").strip()
                rank = (row.get("rank") or "").strip()
                dept = (row.get("department") or "").strip()
                pwd = (row.get("password") or "changeme123").strip()
                # allow role column in CSV but normalize it
                role = safe_role(row.get("role"))
                # admins cannot create users outside their department or create admin/superadmin
                if session.get("role") == "admin":
                    dept = session.get("dept")
                    # admin cannot create admin or superadmin
                    if role != "employee":
                        role = "employee"
                if not unique_id:
                    skipped += 1; continue
                try:
                    cur.execute("INSERT INTO users(name,unique_id,username,password,role,department,rank,status) VALUES(?,?,?,?,?,?,?,?)",
                                (name, unique_id, unique_id, generate_password_hash(pwd), role, dept, rank, "Active"))
                    added += 1
                except Exception:
                    skipped += 1
            conn.commit(); conn.close()
            flash(f"Added {added} users, skipped {skipped} rows","success")
        except Exception as e:
            flash("Failed to process file: "+str(e),"danger")
        return redirect("/upload_users")
    return render_template("upload_users.html")

@app.route("/users")
def users():
    if "uid" not in session:
        return redirect("/login")
    
    if session.get("role") not in ("admin","superadmin"):
        flash("Only admins can view users","danger")
        return redirect("/dashboard")
    
    conn = get_db(); cur = conn.cursor()
    # superadmin sees all; admin sees their department
    if session.get("role")=="superadmin":
        cur.execute("SELECT * FROM users ORDER BY role DESC, department, name")
    else:
        cur.execute("SELECT * FROM users WHERE department=? ORDER BY role, name",(session.get("dept"),))
    rows = cur.fetchall(); conn.close()
    return render_template("users.html", rows=rows)

@app.route("/user/add", methods=["GET","POST"])
def add_user():
    if "uid" not in session or session.get("role") not in ("admin","superadmin"):
        flash("Not authorized","danger")
        return redirect("/dashboard")
    if request.method=="POST":
        name = request.form.get("name","").strip()
        unique_id = request.form.get("unique_id","").strip()
        rank = request.form.get("rank","").strip()
        pwd = request.form.get("password") or "changeme123"
        # requested role from form
        requested_role = safe_role(request.form.get("role"))
        # admin cannot create admin/superadmin; only superadmin can
        if session.get("role") == "admin" and requested_role in ("admin","superadmin"):
            requested_role = "employee"
            flash("Admins can only create normal users in their department. Promote to admin/superadmin requires Super Admin.", "warning")
        dept = request.form.get("department") if session.get("role")=="superadmin" else session.get("dept")
        try:
            conn = get_db(); cur = conn.cursor()
            cur.execute("INSERT INTO users(name,unique_id,username,password,role,department,rank,status) VALUES(?,?,?,?,?,?,?,?)",
                        (name, unique_id, unique_id, generate_password_hash(pwd), requested_role, dept, rank, "Active"))
            conn.commit(); conn.close(); flash("User added successfully","success"); return redirect("/users")
        except Exception as e:
            flash("Error: "+str(e),"danger"); return redirect("/user/add")
    depts = ["FIT", "FFC", "FCE", "FC", "HQ"]
    ranks = ["INSP/RO", "INSP/T", "INSP/C", "INSP/DM", "SI/RO", "SI/T", "SI/C", "SI/PIONEER", 
             "INSP/PIONEER", "SI/DM", "ASI/DM", "ASI/T", "ASI/RO", "ASI/C", "HC/RO", "HC/C", 
             "HC/PIONEER", "CT/PIONEER", "INSP/GD", "SI/GD", "ASI/GD", "CT/GD", "CT/OTHERS"]
    return render_template("add_user.html", depts=depts, ranks=ranks)

@app.route("/user/edit/<int:uid>", methods=["GET","POST"])
def edit_user(uid):
    if "uid" not in session or session.get("role") not in ("admin","superadmin"):
        flash("Not authorized","danger")
        return redirect("/dashboard")
    conn = get_db(); cur = conn.cursor(); cur.execute("SELECT * FROM users WHERE id=?",(uid,))
    user = cur.fetchone()
    if not user:
        conn.close(); flash("User not found","danger"); return redirect("/users")
    # admin may edit only users in same department
    if session.get("role")=="admin" and user["department"]!=session.get("dept"):
        conn.close(); flash("Not authorized","danger"); return redirect("/users")
    if request.method=="POST":
        name = request.form.get("name", user["name"]).strip()
        rank = request.form.get("rank", user["rank"]).strip()
        status = request.form.get("status", user["status"]).strip()
        password = request.form.get("password")
        # only superadmin can change department via the form; admins cannot
        department = request.form.get("department") if session.get("role")=="superadmin" else user["department"]
        try:
            if password:
                cur.execute("UPDATE users SET name=?, rank=?, status=?, password=?, department=? WHERE id=?",
                            (name, rank, status, generate_password_hash(password), department, uid))
            else:
                cur.execute("UPDATE users SET name=?, rank=?, status=?, department=? WHERE id=?",
                            (name, rank, status, department, uid))
            conn.commit(); conn.close(); flash("User updated successfully","success"); return redirect("/users")
        except Exception as e:
            conn.close(); flash("Error: "+str(e),"danger"); return redirect(f"/user/edit/{uid}")
    conn.close()
    ranks = ["INSP/RO", "INSP/T", "INSP/C", "INSP/DM", "SI/RO", "SI/T", "SI/C", "SI/PIONEER", 
             "INSP/PIONEER", "SI/DM", "ASI/DM", "ASI/T", "ASI/RO", "ASI/C", "HC/RO", "HC/C", 
             "HC/PIONEER", "CT/PIONEER", "INSP/GD", "SI/GD", "ASI/GD", "CT/GD", "CT/OTHERS"]
    return render_template("edit_user.html", user=user, ranks=ranks)

@app.route("/user/delete/<int:uid>", methods=["POST"])
def delete_user(uid):
    # only admin/superadmin can delete, with additional checks
    if "uid" not in session or session.get("role") not in ("admin","superadmin"):
        flash("Not authorized","danger")
        return redirect("/dashboard")
    conn = get_db(); cur = conn.cursor(); cur.execute("SELECT * FROM users WHERE id=?",(uid,))
    user = cur.fetchone()
    if not user:
        conn.close(); flash("User not found","danger"); return redirect("/users")
    # admins cannot delete users outside their department
    if session.get("role")=="admin" and user["department"]!=session.get("dept"):
        conn.close(); flash("Not authorized","danger"); return redirect("/users")
    # never allow deletion of superadmin accounts
    if user["role"] == "superadmin":
        conn.close(); flash("Superadmin accounts cannot be deleted.","danger"); return redirect("/users")
    # also prevent self-delete (nice to have)
    if user["id"] == session.get("uid"):
        conn.close(); flash("You cannot delete your own account while logged in.","danger"); return redirect("/users")
    cur.execute("DELETE FROM users WHERE id=?",(uid,))
    conn.commit(); conn.close(); flash("User deleted successfully","success"); return redirect("/users")

@app.route("/apply_leave", methods=["GET","POST"])
def apply_leave():
    # only employees can apply leave
    if "uid" not in session or session.get("role")!="employee":
        flash("Only employees can apply leave","danger")
        return redirect("/dashboard")
    if request.method=="POST":
        p1_from = request.form.get("plan1_from")
        p1_to = request.form.get("plan1_to")
        p2_from = request.form.get("plan2_from")
        p2_to = request.form.get("plan2_to")
        reason = request.form.get("reason")
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO leaves(user_id,department,plan1_from,plan1_to,plan2_from,plan2_to,reason,applied_on) VALUES(?,?,?,?,?,?,?,?)",
                    (session.get("uid"), session.get("dept"), p1_from, p1_to, p2_from, p2_to, reason, datetime.datetime.now().isoformat()))
        conn.commit(); conn.close(); flash("Leave applied successfully","success"); return redirect("/my_leaves")
    return render_template("apply_leave.html")

@app.route("/my_leaves")
def my_leaves():
    if "uid" not in session:
        return redirect("/login")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM leaves WHERE user_id=? ORDER BY applied_on DESC",(session.get("uid"),))
    rows = cur.fetchall(); conn.close()
    return render_template("my_leaves.html", rows=rows)

@app.route("/manage_leaves")
def manage_leaves():
    if "uid" not in session or session.get("role") not in ("admin","superadmin"):
        flash("Not authorized","danger")
        return redirect("/dashboard")
    conn = get_db(); cur = conn.cursor()
    if session.get("role")=="superadmin":
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id ORDER BY applied_on DESC")
    else:
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id WHERE l.department=? ORDER BY applied_on DESC",(session.get("dept"),))
    rows = cur.fetchall(); conn.close()
    return render_template("manage_leaves.html", rows=rows)

@app.route("/change_status/<int:leave_id>/<string:status>", methods=["POST"])
def change_status(leave_id, status):
    if "uid" not in session or session.get("role") not in ("admin","superadmin"):
        flash("Not authorized","danger")
        return redirect("/dashboard")
    
    valid_statuses = ["Pending", "Approved", "Rejected", "Cancelled"]
    if status not in valid_statuses:
        flash("Invalid status","danger")
        return redirect("/manage_leaves")
    
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE leaves SET status=?, approved_by=? WHERE id=?", (status, session.get("uid"), leave_id))
    conn.commit(); conn.close(); 
    flash(f"Leave status updated to {status}","success"); 
    return redirect("/manage_leaves")

@app.route("/reports")
def reports():
    if "uid" not in session:
        return redirect("/login")
    conn = get_db(); cur = conn.cursor()
    if session.get("role")=="superadmin":
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id ORDER BY applied_on DESC")
    elif session.get("role")=="admin":
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id WHERE l.department=? ORDER BY applied_on DESC",(session.get("dept"),))
    else:
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id WHERE l.user_id=? ORDER BY applied_on DESC",(session.get("uid"),))
    rows = cur.fetchall(); conn.close()
    return render_template("reports.html", rows=rows)

def generate_csv(rows):
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(["ID","Employee","Rank","Department","From","To","Reason","Status","Applied On","Approved By"])
    for r in rows:
        writer.writerow([r["id"], r.get("employee_name", r.get("user_id")), r.get("rank",""), r["department"], r.get("plan1_from",""), r.get("plan1_to",""), r.get("reason",""), r.get("status"), r.get("applied_on"), r.get("approved_by","")])
    return output.getvalue().encode("utf-8")


@app.route("/api/department-users/<dept>")
def api_department_users(dept):
    conn = get_db()
    cur = conn.cursor()

    # Fetch all users from this department
    cur.execute("SELECT id, name, rank, dept FROM users WHERE dept=?", (dept,))
    users = cur.fetchall()

    result = []

    for u in users:
        user_id = u[0]

        # Leave stats
        cur.execute("""
            SELECT 
                SUM(CASE WHEN leave_type='CL' AND status='approved' THEN days ELSE 0 END),
                SUM(CASE WHEN leave_type='CL' AND status='pending' THEN days ELSE 0 END),
                SUM(CASE WHEN leave_type='EL' AND status='approved' THEN days ELSE 0 END),
                SUM(CASE WHEN leave_type='EL' AND status='pending' THEN days ELSE 0 END)
            FROM leaves WHERE user_id=?
        """, (user_id,))

        stat = cur.fetchone()
        casual_approved = stat[0] or 0
        casual_pending = stat[1] or 0
        earned_approved = stat[2] or 0
        earned_pending = stat[3] or 0

        # Compute remaining leaves
        casual_remaining = 15 - casual_approved
        earned_remaining = 60 - earned_approved

        result.append({
            "name": u[1],
            "rank": u[2],
            "casual_approved": casual_approved,
            "casual_pending": casual_pending,
            "earned_approved": earned_approved,
            "earned_pending": earned_pending,
            "casual_remaining": casual_remaining,
            "earned_remaining": earned_remaining
        })

    return jsonify(result)


@app.route("/export/<string:fmt>")
def export(fmt):
    if "uid" not in session:
        return redirect("/login")
    conn = get_db(); cur = conn.cursor()
    if session.get("role")=="superadmin":
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id ORDER BY applied_on DESC")
    elif session.get("role")=="admin":
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id WHERE l.department=? ORDER BY applied_on DESC",(session.get("dept"),))
    else:
        cur.execute("SELECT l.*, u.name as employee_name, u.rank FROM leaves l JOIN users u ON l.user_id=u.id WHERE l.user_id=? ORDER BY applied_on DESC",(session.get("uid"),))
    rows = cur.fetchall(); conn.close()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt=="csv":
        data = generate_csv(rows)
        return send_file(io.BytesIO(data), mimetype="text/csv", download_name=f"leave_report_{timestamp}.csv", as_attachment=True)
    elif fmt=="excel":
        try:
            import pandas as pd
            df = pd.DataFrame([dict(r) for r in rows])
            buffer = io.BytesIO(); df.to_excel(buffer, index=False)
            buffer.seek(0)
            return send_file(buffer, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", download_name=f"leave_report_{timestamp}.xlsx", as_attachment=True)
        except Exception:
            data = generate_csv(rows)
            return send_file(io.BytesIO(data), mimetype="text/csv", download_name=f"leave_report_{timestamp}.csv", as_attachment=True)
    elif fmt=="pdf":
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            buffer = io.BytesIO()
            c = canvas.Canvas(buffer, pagesize=A4)
            y = 800
            c.setFont("Helvetica-Bold", 12); c.drawString(40, y, "Leave Report"); y -= 30
            c.setFont("Helvetica", 9)
            for r in rows:
                line = f'{r["id"]} | {r.get("employee_name", r.get("user_id"))} | {r.get("rank","")} | {r["department"]} | {r.get("plan1_from","")} to {r.get("plan1_to","")} | {r["status"]}'
                c.drawString(40, y, line); y -= 14
                if y < 60:
                    c.showPage(); y = 800
            c.save(); buffer.seek(0)
            return send_file(buffer, mimetype="application/pdf", download_name=f"leave_report_{timestamp}.pdf", as_attachment=True)
        except Exception:
            data = generate_csv(rows)
            return send_file(io.BytesIO(data), mimetype="text/csv", download_name=f"leave_report_{timestamp}.csv", as_attachment=True)
    else:
        return "Unsupported format", 400
@app.route("/api/department-leaves/<dept>")
def api_department_leaves(dept):
    if "uid" not in session or session.get("role") not in ("admin","superadmin"):
        return jsonify({"error": "Not authorized"}), 403
    
    conn = get_db()
    cur = conn.cursor()
    
    # Fetch unique employees in this department
    cur.execute("SELECT DISTINCT u.id, u.name FROM users u WHERE u.department=?", (dept,))
    employees = cur.fetchall()
    
    # Fetch all leave requests for this department
    cur.execute("""
        SELECT l.id, l.user_id, l.department, l.plan1_from, l.plan1_to, l.plan2_from, l.plan2_to, 
               l.reason, l.status, u.name as employee_name, u.rank
        FROM leaves l 
        JOIN users u ON l.user_id=u.id 
        WHERE l.department=?
        ORDER BY l.applied_on DESC
    """, (dept,))
    leaves = cur.fetchall()
    conn.close()
    
    return jsonify({
        "employees": [{"id": e[0], "name": e[1]} for e in employees],
        "leaves": [dict(l) for l in leaves]
    })


if __name__=="__main__":
    app.run(debug=True)
