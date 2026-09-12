from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import config
import os
import re
import uuid

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# CREATE FLASK APPLICATION
# ==========================================

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_database():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


# ==========================================
# SUBJECT LIST
# ==========================================

def get_subjects():
    return [
        "English Language",
        "Mathematics",
        "Physics",
        "Chemistry",
        "Biology",
        "Government",
        "Literature-in-English",
        "Yoruba",
        "Commerce",
        "Bookkeeping",
        "Accounting",
        "Agric Science",
        "Technical Drawing"
    ]


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# STUDENT LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template(
            "login.html",
            message="Please enter your email and password."
        )

    connection = None
    cursor = None

    try:
        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                username,
                email,
                password,
                class_name,
                profile_picture,
                failed_attempts
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        user = cursor.fetchone()

        if user is None:
            return render_template(
                "login.html",
                message="Incorrect email or password."
            )

        if user["failed_attempts"] >= 4:
            return redirect(
                url_for(
                    "change_password",
                    email=email
                )
            )

        if not check_password_hash(
            user["password"],
            password
        ):

            new_attempts = user["failed_attempts"] + 1

            cursor.execute(
                """
                UPDATE users
                SET failed_attempts = %s
                WHERE id = %s
                """,
                (
                    new_attempts,
                    user["id"]
                )
            )

            connection.commit()

            if new_attempts >= 4:
                return redirect(
                    url_for(
                        "change_password",
                        email=email
                    )
                )

            remaining = 4 - new_attempts

            return render_template(
                "login.html",
                message=(
                    f"Incorrect password. "
                    f"You have {remaining} attempt(s) remaining."
                )
            )

        cursor.execute(
            """
            UPDATE users
            SET failed_attempts = 0
            WHERE id = %s
            """,
            (user["id"],)
        )

        connection.commit()

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["email"] = user["email"]
        session["class_name"] = user["class_name"]
        session["profile_picture"] = user["profile_picture"]

        return redirect(
            url_for("dashboard")
        )

    except mysql.connector.Error as error:

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==========================================
# STUDENT SIGN UP
# ==========================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "GET":
        return render_template(
            "signup.html"
        )

    username = request.form.get(
        "username",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    class_name = request.form.get(
        "class_name",
        ""
    ).strip()

    profile_picture = request.files.get(
        "profile_picture"
    )

    if not username:
        return render_template(
            "signup.html",
            message="Please enter a username."
        )

    if not email:
        return render_template(
            "signup.html",
            message="Please enter your email."
        )

    if not password:
        return render_template(
            "signup.html",
            message="Please create a password."
        )

    if not class_name:
        return render_template(
            "signup.html",
            message="Please select your class."
        )

    if not profile_picture or not profile_picture.filename:
        return render_template(
            "signup.html",
            message="Please select a profile picture."
        )

    if password != confirm_password:
        return render_template(
            "signup.html",
            message="Password mismatch."
        )

    has_letter = re.search(
        r"[A-Za-z]",
        password
    )

    has_number = re.search(
        r"[0-9]",
        password
    )

    has_symbol = re.search(
        r"[^A-Za-z0-9]",
        password
    )

    if not (
        has_letter
        and has_number
        and has_symbol
    ):
        return render_template(
            "signup.html",
            message=(
                "Password must contain "
                "an alphabet, number and symbol."
            )
        )

    allowed_classes = [
        "JSS1",
        "JSS2",
        "JSS3",
        "SS1",
        "SS2",
        "SS3"
    ]

    if class_name not in allowed_classes:
        return render_template(
            "signup.html",
            message="Please select a valid class."
        )

    allowed_extensions = [
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp"
    ]

    original_name = profile_picture.filename

    extension = os.path.splitext(
        original_name
    )[1].lower()

    if extension not in allowed_extensions:
        return render_template(
            "signup.html",
            message=(
                "Please upload a JPG, JPEG, PNG, "
                "GIF or WEBP image."
            )
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            return render_template(
                "signup.html",
                message=(
                    "An account with this email "
                    "already exists."
                )
            )

        filename = (
            str(uuid.uuid4())
            + extension
        )

        upload_folder = os.path.join(
            app.root_path,
            "static",
            "uploads"
        )

        os.makedirs(
            upload_folder,
            exist_ok=True
        )

        image_path = os.path.join(
            upload_folder,
            filename
        )

        profile_picture.save(
            image_path
        )

        hashed_password = generate_password_hash(
            password
        )

        cursor.execute(
            """
            INSERT INTO users (
                username,
                email,
                password,
                class_name,
                profile_picture,
                failed_attempts
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                username,
                email,
                hashed_password,
                class_name,
                filename,
                0
            )
        )

        connection.commit()

        return render_template(
            "login.html",
            message=(
                "Account created successfully! "
                "Please login."
            )
        )

    except mysql.connector.Error as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    except Exception as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==========================================
# CHANGE PASSWORD CENTER
# ==========================================

@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
def change_password():

    email = request.args.get(
        "email",
        ""
    )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip()

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if new_password != confirm_password:
            return render_template(
                "change_password.html",
                email=email,
                message="Password mismatch."
            )

        has_letter = re.search(
            r"[A-Za-z]",
            new_password
        )

        has_number = re.search(
            r"[0-9]",
            new_password
        )

        has_symbol = re.search(
            r"[^A-Za-z0-9]",
            new_password
        )

        if not (
            has_letter
            and has_number
            and has_symbol
        ):
            return render_template(
                "change_password.html",
                email=email,
                message=(
                    "Password must contain "
                    "an alphabet, number and symbol."
                )
            )

        connection = None
        cursor = None

        try:

            connection = get_database()

            cursor = connection.cursor()

            hashed_password = generate_password_hash(
                new_password
            )

            cursor.execute(
                """
                UPDATE users
                SET
                    password = %s,
                    failed_attempts = 0
                WHERE email = %s
                """,
                (
                    hashed_password,
                    email
                )
            )

            connection.commit()

            return render_template(
                "login.html",
                message=(
                    "Password changed successfully! "
                    "Please login."
                )
            )

        except mysql.connector.Error as error:

            return f"""
            <h2>Database error</h2>
            <p>{error}</p>
            """

        finally:

            if cursor is not None:
                cursor.close()

            if connection is not None:
                connection.close()

    return render_template(
        "change_password.html",
        email=email
    )


# ==========================================
# STUDENT DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html"
    )


# ==========================================
# STUDENT PROFILE
# ==========================================

@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    return render_template(
        "profile.html"
    )


# ==========================================
# STUDENT MIDTERM RESULT
# ==========================================

@app.route("/midterm-result")
def midterm_result():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                subject,
                score,
                uploaded_at
            FROM midterm_results
            WHERE student_id = %s
            ORDER BY id ASC
            """,
            (session["user_id"],)
        )

        results = cursor.fetchall()

        return render_template(
            "midterm_result.html",
            results=results
        )

    except mysql.connector.Error as error:

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==========================================
# STUDENT EXAM RESULT
# ==========================================

@app.route("/exam-result")
def exam_result():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                subject,
                score,
                uploaded_at
            FROM exam_results
            WHERE student_id = %s
            ORDER BY id ASC
            """,
            (session["user_id"],)
        )

        results = cursor.fetchall()

        return render_template(
            "exam_result.html",
            results=results
        )

    except mysql.connector.Error as error:

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==========================================
# ADMIN LOGIN
# ==========================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    if request.method == "GET":
        return render_template(
            "admin_login.html"
        )

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    if not username or not password:
        return render_template(
            "admin_login.html",
            message=(
                "Please enter your username "
                "and password."
            )
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                username,
                password
            FROM admins
            WHERE username = %s
            """,
            (username,)
        )

        admin = cursor.fetchone()

        if admin is None:
            return render_template(
                "admin_login.html",
                message=(
                    "Incorrect admin username "
                    "or password."
                )
            )

        if not check_password_hash(
            admin["password"],
            password
        ):
            return render_template(
                "admin_login.html",
                message=(
                    "Incorrect admin username "
                    "or password."
                )
            )

        session["admin_id"] = admin["id"]

        session["admin_username"] = (
            admin["username"]
        )

        return redirect(
            url_for("admin_dashboard")
        )

    except mysql.connector.Error as error:

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin/dashboard")
def admin_dashboard():

    if "admin_id" not in session:
        return redirect(
            url_for("admin_login")
        )

    return render_template(
        "admin_dashboard.html"
    )


# ==========================================
# ADMIN UPLOAD MIDTERM RESULTS
# ==========================================

@app.route(
    "/admin/upload-midterm",
    methods=["GET", "POST"]
)
def upload_midterm():

    if "admin_id" not in session:
        return redirect(
            url_for("admin_login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                username,
                email,
                class_name
            FROM users
            ORDER BY username ASC
            """
        )

        students = cursor.fetchall()

        subjects = get_subjects()

        if request.method == "GET":

            return render_template(
                "upload_midterm.html",
                students=students,
                subjects=subjects
            )

        student_id = request.form.get(
            "student_id",
            ""
        ).strip()

        if not student_id:

            return render_template(
                "upload_midterm.html",
                students=students,
                subjects=subjects,
                message="Please select a student."
            )

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
            """,
            (student_id,)
        )

        student = cursor.fetchone()

        if student is None:

            return render_template(
                "upload_midterm.html",
                students=students,
                subjects=subjects,
                message="Student not found."
            )

        scores = {}

        for subject in subjects:

            score_text = request.form.get(
                subject,
                ""
            ).strip()

            if not score_text:

                return render_template(
                    "upload_midterm.html",
                    students=students,
                    subjects=subjects,
                    message=(
                        f"Please enter a score "
                        f"for {subject}."
                    )
                )

            try:
                score = float(score_text)

            except ValueError:

                return render_template(
                    "upload_midterm.html",
                    students=students,
                    subjects=subjects,
                    message=(
                        f"Invalid score for "
                        f"{subject}."
                    )
                )

            if score < 0 or score > 100:

                return render_template(
                    "upload_midterm.html",
                    students=students,
                    subjects=subjects,
                    message=(
                        f"{subject} score must "
                        f"be between 0 and 100."
                    )
                )

            scores[subject] = score

        cursor.execute(
            """
            DELETE FROM midterm_results
            WHERE student_id = %s
            """,
            (student_id,)
        )

        for subject in subjects:

            cursor.execute(
                """
                INSERT INTO midterm_results (
                    student_id,
                    subject,
                    score
                )
                VALUES (
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    student_id,
                    subject,
                    scores[subject]
                )
            )

        connection.commit()

        return render_template(
            "upload_midterm.html",
            students=students,
            subjects=subjects,
            message=(
                "Midterm result saved successfully!"
            )
        )

    except mysql.connector.Error as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    except Exception as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==========================================
# ADMIN UPLOAD EXAM RESULTS
# ==========================================

@app.route(
    "/admin/upload-exam",
    methods=["GET", "POST"]
)
def upload_exam():

    if "admin_id" not in session:
        return redirect(
            url_for("admin_login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                username,
                email,
                class_name
            FROM users
            ORDER BY username ASC
            """
        )

        students = cursor.fetchall()

        subjects = get_subjects()

        if request.method == "GET":

            return render_template(
                "upload_exam.html",
                students=students,
                subjects=subjects
            )

        student_id = request.form.get(
            "student_id",
            ""
        ).strip()

        if not student_id:

            return render_template(
                "upload_exam.html",
                students=students,
                subjects=subjects,
                message="Please select a student."
            )

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
            """,
            (student_id,)
        )

        student = cursor.fetchone()

        if student is None:

            return render_template(
                "upload_exam.html",
                students=students,
                subjects=subjects,
                message="Student not found."
            )

        scores = {}

        for subject in subjects:

            score_text = request.form.get(
                subject,
                ""
            ).strip()

            if not score_text:

                return render_template(
                    "upload_exam.html",
                    students=students,
                    subjects=subjects,
                    message=(
                        f"Please enter a score "
                        f"for {subject}."
                    )
                )

            try:
                score = float(score_text)

            except ValueError:

                return render_template(
                    "upload_exam.html",
                    students=students,
                    subjects=subjects,
                    message=(
                        f"Invalid score for "
                        f"{subject}."
                    )
                )

            if score < 0 or score > 100:

                return render_template(
                    "upload_exam.html",
                    students=students,
                    subjects=subjects,
                    message=(
                        f"{subject} score must "
                        f"be between 0 and 100."
                    )
                )

            scores[subject] = score

        cursor.execute(
            """
            DELETE FROM exam_results
            WHERE student_id = %s
            """,
            (student_id,)
        )

        for subject in subjects:

            cursor.execute(
                """
                INSERT INTO exam_results (
                    student_id,
                    subject,
                    score
                )
                VALUES (
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    student_id,
                    subject,
                    scores[subject]
                )
            )

        connection.commit()

        return render_template(
            "upload_exam.html",
            students=students,
            subjects=subjects,
            message=(
                "Exam result saved successfully!"
            )
        )

    except mysql.connector.Error as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    except Exception as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==================================================
# VIEW ALL STUDENTS - ADMIN
# ==================================================

@app.route("/admin/students")
def admin_students():

    if "admin_id" not in session:
        return redirect(
            url_for("admin_login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                username,
                email,
                class_name,
                profile_picture,
                created_at
            FROM users
            ORDER BY username ASC
            """
        )

        students = cursor.fetchall()

        return render_template(
            "admin_students.html",
            students=students
        )

    except mysql.connector.Error as error:

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==================================================
# MANAGE RESULTS - ADMIN
# ==================================================

@app.route("/admin/manage-results")
def manage_results():

    if "admin_id" not in session:
        return redirect(
            url_for("admin_login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        # ------------------------------------------
        # GET MIDTERM RESULTS
        # ------------------------------------------

        cursor.execute(
            """
            SELECT
                midterm_results.id,
                midterm_results.student_id,
                users.username,
                users.email,
                users.class_name,
                midterm_results.subject,
                midterm_results.score,
                midterm_results.uploaded_at
            FROM midterm_results
            INNER JOIN users
                ON midterm_results.student_id = users.id
            ORDER BY
                users.username ASC,
                midterm_results.id ASC
            """
        )

        midterm_results = cursor.fetchall()

        # ------------------------------------------
        # GET EXAM RESULTS
        # ------------------------------------------

        cursor.execute(
            """
            SELECT
                exam_results.id,
                exam_results.student_id,
                users.username,
                users.email,
                users.class_name,
                exam_results.subject,
                exam_results.score,
                exam_results.uploaded_at
            FROM exam_results
            INNER JOIN users
                ON exam_results.student_id = users.id
            ORDER BY
                users.username ASC,
                exam_results.id ASC
            """
        )

        exam_results = cursor.fetchall()

        return render_template(
            "manage_results.html",
            midterm_results=midterm_results,
            exam_results=exam_results
        )

    except mysql.connector.Error as error:

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==================================================
# DELETE MIDTERM RESULT
# ==================================================

@app.route(
    "/admin/delete-midterm/<int:result_id>",
    methods=["POST"]
)
def delete_midterm(result_id):

    if "admin_id" not in session:
        return redirect(
            url_for("admin_login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM midterm_results
            WHERE id = %s
            """,
            (result_id,)
        )

        connection.commit()

        return redirect(
            url_for("manage_results")
        )

    except mysql.connector.Error as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==================================================
# DELETE EXAM RESULT
# ==================================================

@app.route(
    "/admin/delete-exam/<int:result_id>",
    methods=["POST"]
)
def delete_exam(result_id):

    if "admin_id" not in session:
        return redirect(
            url_for("admin_login")
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM exam_results
            WHERE id = %s
            """,
            (result_id,)
        )

        connection.commit()

        return redirect(
            url_for("manage_results")
        )

    except mysql.connector.Error as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==================================================
# CREATE ADMIN ACCOUNT
# ==================================================

@app.route(
    "/admin/create",
    methods=["GET", "POST"]
)
def create_admin():

    if request.method == "GET":

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Create Admin</title>
        </head>

        <body>

            <h2>Create First Admin Account</h2>

            <form method="POST">

                <label>Username:</label>
                <br>

                <input
                    type="text"
                    name="username"
                    required
                >

                <br><br>

                <label>Password:</label>
                <br>

                <input
                    type="password"
                    name="password"
                    required
                >

                <br><br>

                <button type="submit">
                    Create Admin
                </button>

            </form>

        </body>
        </html>
        """

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    if not username or not password:
        return "Username and password are required."

    has_letter = re.search(
        r"[A-Za-z]",
        password
    )

    has_number = re.search(
        r"[0-9]",
        password
    )

    has_symbol = re.search(
        r"[^A-Za-z0-9]",
        password
    )

    if not (
        has_letter
        and has_number
        and has_symbol
    ):
        return (
            "Password must contain "
            "an alphabet, number and symbol."
        )

    connection = None
    cursor = None

    try:

        connection = get_database()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT id
            FROM admins
            WHERE username = %s
            """,
            (username,)
        )

        existing_admin = cursor.fetchone()

        if existing_admin:
            return (
                "An admin with this username "
                "already exists."
            )

        hashed_password = generate_password_hash(
            password
        )

        cursor.execute(
            """
            INSERT INTO admins (
                username,
                password
            )
            VALUES (
                %s,
                %s
            )
            """,
            (
                username,
                hashed_password
            )
        )

        connection.commit()

        return """
        <h2>Admin account created successfully!</h2>

        <p>
            You can now login to the Admin Portal.
        </p>

        <a href="/admin/login">
            Go to Admin Login
        </a>
        """

    except mysql.connector.Error as error:

        if connection is not None:
            connection.rollback()

        return f"""
        <h2>Database error</h2>
        <p>{error}</p>
        """

    finally:

        if cursor is not None:
            cursor.close()

        if connection is not None:
            connection.close()


# ==========================================
# ADMIN LOGOUT
# ==========================================

@app.route("/admin/logout")
def admin_logout():

    session.pop(
        "admin_id",
        None
    )

    session.pop(
        "admin_username",
        None
    )

    return redirect(
        url_for("admin_login")
    )


# ==========================================
# DATABASE TEST
# ==========================================

@app.route("/database-test")
def database_test():

    try:

        connection = get_database()

        if connection.is_connected():

            connection.close()

            return (
                "Database connected successfully!"
            )

    except mysql.connector.Error as error:

        return (
            f"Database connection failed: {error}"
        )

    return "Database connection failed."


# ==========================================
# STUDENT LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )