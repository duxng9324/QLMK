from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import sqlite3
import os

# Khởi tạo Flask app
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Thay đổi cho bảo mật

# Khởi tạo Argon2
ph = PasswordHasher()

# Cấu hình cơ sở dữ liệu SQLite
DB_PATH = "password_manager.db"

# Khởi tạo cơ sở dữ liệu
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        print("Table 'users' created or already exists.")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        print("Table 'passwords' created or already exists.")
        
    except sqlite3.OperationalError as e:
        print("Error while creating tables:", e)
    finally:
        conn.commit()
        conn.close()


# Forms sử dụng Flask-WTF
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# Routes
@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("welcome"))
    return redirect(url_for("dashboard"))


@app.route("/welcome")
def welcome():
    return render_template("welcome.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            password_hash = ph.hash(password)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            conn.close()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username is already taken.", "danger")
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            password_hash = row[0]
            try:
                ph.verify(password_hash, password)
                session["username"] = username
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
            except VerifyMismatchError:
                flash("Invalid password.", "danger")
        else:
            flash("Username not found.", "danger")
    return render_template("login.html", form=form)

@app.route("/dashboard")
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    search_query = request.form.get("search", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, password_hash FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?) AND service LIKE ?", (username, f"%{search_query}%"))
    passwords = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", username=username, passwords=passwords)


@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/add_password", methods=["GET", "POST"])
def add_password():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        service = request.form.get("service")
        password = request.form.get("password")
        username = session["username"]

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_id = cursor.fetchone()[0]

        password_hash = ph.hash(password)
        cursor.execute("INSERT INTO passwords (user_id, service, password_hash) VALUES (?, ?, ?)", 
                       (user_id, service, password_hash))
        conn.commit()
        conn.close()
        flash("Password added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_password.html")

@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Lấy id người dùng
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = cursor.fetchone()[0]

    # Xóa tất cả mật khẩu liên quan đến người dùng
    cursor.execute("DELETE FROM passwords WHERE user_id = ?", (user_id,))
    
    # Xóa tài khoản người dùng
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

    conn.commit()
    conn.close()

    # Đăng xuất người dùng sau khi xóa tài khoản
    session.pop("username", None)
    flash("Your account has been deleted successfully.", "info")
    return redirect(url_for("welcome"))

@app.route("/delete_password/<int:password_id>", methods=["POST"])
def delete_password(password_id):
    if "username" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Xóa mật khẩu theo id
    cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
    conn.commit()
    conn.close()

    flash("Password deleted successfully.", "info")
    return redirect(url_for("dashboard"))

@app.route("/edit_password/<int:password_id>", methods=["GET", "POST"])
def edit_password(password_id):
    if "username" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT service, password_hash FROM passwords WHERE id = ?", (password_id,))
    password = cursor.fetchone()
    conn.close()

    if not password:
        flash("Password not found.", "danger")
        return redirect(url_for("dashboard"))

    form = FlaskForm()
    if request.method == "POST":
        new_password = request.form.get("password")
        new_password_hash = ph.hash(new_password)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE passwords SET password_hash = ? WHERE id = ?", (new_password_hash, password_id))
        conn.commit()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_password.html", password=password)



# Khởi tạo cơ sở dữ liệu nếu chưa tồn tại
if not os.path.exists(DB_PATH):
    init_db()

# Chạy ứng dụng
if __name__ == "__main__":
    app.run(debug=True)
