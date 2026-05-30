from flask import Flask, render_template_string, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong random key

ADMIN_PASSWORD_HASH = generate_password_hash("replace_with_strong_password")

def get_db():
    conn = sqlite3.connect("academy.db")
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT UNIQUE NOT NULL,
            phone    TEXT NOT NULL,
            password TEXT NOT NULL,
            approved INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ── Templates ──────────────────────────────────────────────

HOME_PAGE = """
<!DOCTYPE html>
<html dir="rtl">
<head><meta charset="UTF-8"><title>Youssef Alaa Academy</title></head>
<body>
<h1>Youssef Alaa Academy</h1>
<a href="/admin">⚙️</a>

<h2>تسجيل الدخول</h2>
<form method="post" action="/login">
    <input name="name" placeholder="اسم المستخدم" required>
    <input type="password" name="password" placeholder="كلمة المرور" required>
    <button>دخول</button>
</form>

<h2>مستخدم جديد</h2>
<form method="post" action="/register">
    <input name="name" placeholder="الاسم" required>
    <input name="phone" placeholder="رقم الهاتف" required>
    <input type="password" name="password" placeholder="كلمة المرور" required>
    <button>تسجيل</button>
</form>
</body>
</html>
"""

ADMIN_LOGIN = """
<!DOCTYPE html>
<html dir="rtl">
<head><meta charset="UTF-8"><title>Admin</title></head>
<body>
<form method="post">
    <h2>دخول المشرف</h2>
    <input type="password" name="password" required>
    <button>دخول</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body>
</html>
"""

ADMIN_PANEL = """
<!DOCTYPE html>
<html dir="rtl">
<head><meta charset="UTF-8"><title>لوحة المشرف</title></head>
<body>
<h2>لوحة المشرف</h2>
{% for user in users %}
<p>
    {{ user['name'] }} | {{ user['phone'] }} —
    {% if user['approved'] %}
        <strong>معتمد</strong>
    {% else %}
        قيد المراجعة
        <form method="post" action="/approve/{{ user['id'] }}" style="display:inline">
            <button type="submit">قبول</button>
        </form>
    {% endif %}
</p>
{% endfor %}
<a href="/admin/logout">تسجيل خروج</a>
</body>
</html>
"""

# ── Routes ─────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template_string(HOME_PAGE)


@app.route("/register", methods=["POST"])
def register():
    name     = request.form.get("name", "").strip()
    phone    = request.form.get("phone", "").strip()
    password = request.form.get("password", "")

    if not name or not phone or not password:
        return "جميع الحقول مطلوبة", 400

    hashed = generate_password_hash(password)

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (name, phone, password) VALUES (?, ?, ?)",
            (name, phone, hashed)
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return "اسم المستخدم مستخدم بالفعل", 409

    return "تم إرسال الطلب للمراجعة"


@app.route("/login", methods=["POST"])
def login():
    name     = request.form.get("name", "").strip()
    password = request.form.get("password", "")

    conn = get_db()
    user = conn.execute(
        "SELECT password, approved FROM users WHERE name = ?", (name,)
    ).fetchone()
    conn.close()

    # Always run check_password_hash to avoid timing attacks
    if user is None or not check_password_hash(user["password"], password):
        return "بيانات غير صحيحة", 401

    if user["approved"] == 0:
        return "حسابك قيد المراجعة"

    return "تم تسجيل الدخول بنجاح"


@app.route("/admin", methods=["GET", "POST"])
def admin():
    error = None

    if request.method == "POST":
        password = request.form.get("password", "")
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["admin"] = True
        else:
            error = "كلمة المرور غير صحيحة"

    if not session.get("admin"):
        return render_template_string(ADMIN_LOGIN, error=error)

    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    return render_template_string(ADMIN_PANEL, users=users)


@app.route("/approve/<int:user_id>", methods=["POST"])  # POST only
def approve(user_id):
    if not session.get("admin"):
        return redirect("/admin")

    conn = get_db()
    conn.execute("UPDATE users SET approved = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    return redirect("/admin")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin")


if __name__ == "__main__":
    app.run(debug=False)  # debug=False in production
