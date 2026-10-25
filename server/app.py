import os
import re
import json
import secrets
import sqlite3
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv
from functools import wraps
from hmac import compare_digest

from flask import Flask, jsonify, request, session, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "trustvault.db"
load_dotenv(BASE_DIR / ".env")
STORAGE_DIR = BASE_DIR / "storage"
SMTP_HOST = os.getenv("TRUSTVAULT_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("TRUSTVAULT_SMTP_PORT", "465"))
SMTP_USERNAME = os.getenv("TRUSTVAULT_SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("TRUSTVAULT_SMTP_PASSWORD", "")


def send_reset_email(recipient_email, reset_link):
    message = EmailMessage()
    message["Subject"] = "TrustVault Password Reset"
    message["From"] = SMTP_USERNAME
    message["To"] = recipient_email

    message.set_content(
        "We received a request to reset your TrustVault password.\n\n"
        f"Use this link to reset your password:\n{reset_link}\n\n"
        "This link expires in 30 minutes. If you did not request this, "
        "you can ignore this email."
    )

    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)

STORAGE_DIR.mkdir(parents=True, exist_ok=True)

secret_key = os.environ.get("TRUSTVAULT_SECRET_KEY", "").strip()
if not secret_key:
    raise RuntimeError(
        "TRUSTVAULT_SECRET_KEY must be configured in server/.env "
        "or the deployment environment."
    )

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None" if os.environ.get("TRUSTVAULT_HTTPS", "0") == "1" else "Lax",
    SESSION_COOKIE_SECURE=os.environ.get("TRUSTVAULT_HTTPS", "0") == "1",
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
)


ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "https://trust-vault-five-beta.vercel.app",
    "https://trust-vault-6ivgozj9b-poornimamoparthi.vercel.app",
]


ALLOWED_EXTENSIONS = {
    ".pdf", ".txt", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx",
}

CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True,
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


# ---------------- DATABASE ----------------

def get_db():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


# ---------------- AUDIT LOGGING ----------------

def write_audit_log(
    connection,
    actor_id,
    action,
    outcome,
    document_id=None,
    target_user_id=None,
    details=None,
):
    """Create an audit record linked to the previous record by SHA-256."""

    details_json = json.dumps(
        details or {},
        sort_keys=True,
        separators=(",", ":"),
    )

    previous = connection.execute(
        """
        SELECT entry_hash
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    previous_hash = previous["entry_hash"] if previous else None

    record = {
        "actor_id": actor_id,
        "action": action,
        "document_id": document_id,
        "target_user_id": target_user_id,
        "outcome": outcome,
        "details": details_json,
        "previous_hash": previous_hash,
    }

    canonical_record = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
    )

    entry_hash = hashlib.sha256(
        canonical_record.encode("utf-8")
    ).hexdigest()

    connection.execute(
        """
        INSERT INTO audit_logs (
            actor_id,
            action,
            document_id,
            target_user_id,
            outcome,
            details,
            previous_hash,
            entry_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            action,
            document_id,
            target_user_id,
            outcome,
            details_json,
            previous_hash,
            entry_hash,
        ),
    )

def verify_audit_chain(connection):
    """Verify audit record hashes and links between records."""

    rows = connection.execute(
        """
        SELECT id, actor_id, action, document_id, target_user_id,
               outcome, details, previous_hash, entry_hash
        FROM audit_logs
        ORDER BY id ASC
        """
    ).fetchall()

    expected_previous_hash = None

    for row in rows:
        if row["previous_hash"] != expected_previous_hash:
            return False, row["id"]

        record = {
            "actor_id": row["actor_id"],
            "action": row["action"],
            "document_id": row["document_id"],
            "target_user_id": row["target_user_id"],
            "outcome": row["outcome"],
            "details": row["details"],
            "previous_hash": row["previous_hash"],
        }

        canonical_record = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
        )

        calculated_hash = hashlib.sha256(
            canonical_record.encode("utf-8")
        ).hexdigest()

        if calculated_hash != row["entry_hash"]:
            return False, row["id"]

        expected_previous_hash = row["entry_hash"]

    return True, None


# ---------------- HELPERS ----------------

def error(message, status=400):
    return jsonify({"error": message}), status


def csrf_protected(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            supplied_token = request.headers.get("X-CSRF-Token", "")
            session_token = session.get("csrf_token", "")

            if (
                not supplied_token
                or not session_token
                or not compare_digest(supplied_token, session_token)
            ):
                return error("Invalid or missing CSRF token.", 403)

        return function(*args, **kwargs)

    return wrapper


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return error("Please log in first.", 401)

        return function(*args, **kwargs)

    return wrapper


# ---------------- HOME AND HEALTH ----------------

@app.get("/")
def home():
    return jsonify({
        "app": "TrustVault",
        "status": "running",
        "message": "TrustVault backend is ready",
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "healthy"})


@app.get("/api/csrf")
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    response = jsonify({
        "csrf_token": session["csrf_token"]
    })
    response.headers["Cache-Control"] = "no-store"

    return response


# ---------------- USER REGISTRATION ----------------

@app.post("/api/auth/register")
@csrf_protected
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("Send a valid JSON request.")

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not all(
        isinstance(value, str)
        for value in (username, email, password)
    ):
        return error("Username, email, and password are required.")

    username = username.strip()
    email = email.strip().lower()

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return error(
            "Username must be 3–30 letters, numbers, or underscores."
        )

    if len(email) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email,
    ):
        return error("Enter a valid email address.")

    if len(password) < 12 or len(password) > 128:
        return error("Password must contain 12–128 characters.")

    password_hash = generate_password_hash(password)
    connection = get_db()

    try:
        cursor = connection.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, 'owner')
            """,
            (username, email, password_hash),
        )

        connection.commit()
        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        connection.rollback()
        return error(
            "Username or email is already registered.",
            409,
        )

    finally:
        connection.close()

    session.clear()
    session["user_id"] = user_id
    session["csrf_token"] = secrets.token_urlsafe(32)

    response = jsonify({
        "message": "Account created successfully.",
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "role": "owner",
        },
        "csrf_token": session["csrf_token"],
    })

    response.headers["Cache-Control"] = "no-store"

    return response, 201


# ---------------- USER LOGIN ----------------

@app.post("/api/auth/login")
@csrf_protected
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("Send a valid JSON request.")

    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return error("Email and password are required.")

    connection = get_db()

    try:
        user = connection.execute(
            """
            SELECT id, username, email, password_hash, role
            FROM users
            WHERE email = ?
            """,
            (email.strip().lower(),),
        ).fetchone()

    finally:
        connection.close()

    if not user or not check_password_hash(
        user["password_hash"],
        password,
    ):
        return error("Invalid email or password.", 401)

    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)

    response = jsonify({
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        },
        "csrf_token": session["csrf_token"],
    })

    response.headers["Cache-Control"] = "no-store"

    return response

# ---------------- PASSWORD RESET REQUEST ----------------

@app.post("/api/auth/forgot-password")
@csrf_protected
def forgot_password():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("Send a valid JSON request.")

    email = data.get("email")

    if not isinstance(email, str) or len(email) > 254:
        return error("Enter a valid email address.")

    email = email.strip().lower()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return error("Enter a valid email address.")

    connection = get_db()

    try:
        user = connection.execute(
            "SELECT id, email FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(
                raw_token.encode("utf-8")
            ).hexdigest()

            expires_at = (
                datetime.now(timezone.utc) + timedelta(minutes=30)
            ).isoformat()

            connection.execute(
                """
                INSERT INTO password_reset_tokens
                    (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
                """,
                (user["id"], token_hash, expires_at),
            )
            connection.commit()

    finally:
        connection.close()

    if user:
        frontend_url = os.environ.get(
            "TRUSTVAULT_FRONTEND_URL",
            "http://localhost:5173",
        ).strip().rstrip("/")
        reset_link = (
            f"{frontend_url}/?reset_token={raw_token}"
        )

        try:
            send_reset_email(user["email"], reset_link)
        except Exception:
            app.logger.exception("Password reset email could not be sent")
            connection = get_db()
            try:
                connection.execute(
                    """
                    DELETE FROM password_reset_tokens
                    WHERE token_hash = ? AND used_at IS NULL
                    """,
                    (token_hash,),
                )
                connection.commit()
            finally:
                connection.close()
            return error("Unable to send reset email. Check Gmail configuration.", 500)

    return jsonify({
        "message": (
            "If that email is registered, a password reset link will be sent."
        )
    })

# ---------------- COMPLETE PASSWORD RESET ----------------

@app.post("/api/auth/reset-password")
@csrf_protected
def reset_password():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("Send a valid JSON request.")

    token = data.get("token")
    new_password = data.get("password")

    if not isinstance(token, str) or not token:
        return error("Reset link is invalid or expired.")

    if not isinstance(new_password, str):
        return error("Enter a new password.")

    if len(new_password) < 12 or len(new_password) > 128:
        return error("Password must contain 12–128 characters.")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    connection = get_db()

    try:
        connection.execute("BEGIN IMMEDIATE")

        reset_record = connection.execute(
            """
            SELECT id, user_id, expires_at, used_at
            FROM password_reset_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()

        if not reset_record or reset_record["used_at"] is not None:
            connection.rollback()
            return error("Reset link is invalid or expired.", 400)

        expires_at = datetime.fromisoformat(reset_record["expires_at"])

        if expires_at <= datetime.now(timezone.utc):
            connection.rollback()
            return error("Reset link is invalid or expired.", 400)

        password_hash = generate_password_hash(new_password)

        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, reset_record["user_id"]),
        )

        connection.execute(
            """
            UPDATE password_reset_tokens
            SET used_at = ?
            WHERE id = ? AND used_at IS NULL
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                reset_record["id"],
            ),
        )

        # Invalidate any other outstanding reset links for this user.
        connection.execute(
            """
            UPDATE password_reset_tokens
            SET used_at = ?
            WHERE user_id = ? AND used_at IS NULL
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                reset_record["user_id"],
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        app.logger.exception("Password reset failed")
        return error("Unable to reset password. Please try again.", 500)

    finally:
        connection.close()

    return jsonify({
        "message": "Password reset successful. Please log in with your new password."
    })


# ---------------- USER LOGOUT ----------------

@app.post("/api/auth/logout")
@csrf_protected
@login_required
def logout():
    session.clear()

    return jsonify({
        "message": "Logged out successfully."
    })


# ---------------- CURRENT USER ----------------

@app.get("/api/auth/me")
@login_required
def current_user():
    connection = get_db()

    try:
        user = connection.execute(
            """
            SELECT id, username, email, role
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],),
        ).fetchone()

    finally:
        connection.close()

    if user is None:
        session.clear()
        return error(
            "Account not found. Please log in again.",
            401,
        )

    return jsonify({
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        }
    })


# ---------------- DOCUMENT UPLOAD ----------------

@app.post("/api/documents")
@csrf_protected
@login_required
def upload_document():
    uploaded_file = request.files.get("file")
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "General").strip()

    if uploaded_file is None or not uploaded_file.filename:
        return error("Please select a file.")

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        return error("Invalid filename.")

    extension = Path(original_filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        return error("This file type is not allowed.")

    if not title or len(title) > 150:
        return error("Title must contain 1–150 characters.")

    if not category or len(category) > 50:
        return error("Category must contain 1–50 characters.")

    file_data = uploaded_file.read()

    if not file_data:
        return error("Empty files cannot be uploaded.")

    if len(file_data) > 10 * 1024 * 1024:
        return error("File exceeds the 10 MB limit.", 413)

    stored_filename = secrets.token_hex(24) + extension
    file_hash = hashlib.sha256(file_data).hexdigest()
    storage_path = STORAGE_DIR / stored_filename

    connection = get_db()
    file_saved = False

    try:
        with storage_path.open("xb") as file_handle:
            file_handle.write(file_data)

        file_saved = True

        cursor = connection.execute(
            """
            INSERT INTO documents (
                owner_id,
                title,
                category,
                original_filename,
                stored_filename,
                content_type,
                file_size,
                sha256
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                title,
                category,
                original_filename,
                stored_filename,
                uploaded_file.mimetype or "application/octet-stream",
                len(file_data),
                file_hash,
            ),
        )

        document_id = cursor.lastrowid

        write_audit_log(
            connection,
            actor_id=session["user_id"],
            action="document_upload",
            outcome="success",
            document_id=document_id,
            details={
                "filename": original_filename,
                "file_size": len(file_data),
                "sha256": file_hash,
            },
        )

        connection.commit()

        return jsonify({
            "message": "Document uploaded successfully.",
            "document": {
                "id": document_id,
                "title": title,
                "category": category,
                "filename": original_filename,
                "file_size": len(file_data),
                "sha256": file_hash,
            },
        }), 201

    except sqlite3.IntegrityError:
        connection.rollback()

        if file_saved:
            storage_path.unlink(missing_ok=True)

        return error("Could not save document information.", 400)

    except OSError:
        connection.rollback()

        if file_saved:
            storage_path.unlink(missing_ok=True)

        return error("Could not store the uploaded file.", 500)

    finally:
        connection.close()


# ---------------- LIST DOCUMENTS ----------------

@app.get("/api/documents")
@login_required
def list_documents():
    connection = get_db()
    user_id = int(session["user_id"])

    try:
        rows = connection.execute(
            """
            SELECT
                d.id,
                d.owner_id,
                d.title,
                d.category,
                d.original_filename,
                d.content_type,
                d.file_size,
                d.sha256,
                d.created_at,
                CASE
                    WHEN d.owner_id = ? THEN 'owner'
                    ELSE p.access_level
                END AS access_level
            FROM documents AS d
            LEFT JOIN document_permissions AS p
                ON p.document_id = d.id
               AND p.user_id = ?
            WHERE d.owner_id = ?
               OR p.user_id = ?
            ORDER BY d.created_at DESC, d.id DESC
            """,
            (user_id, user_id, user_id, user_id),
        ).fetchall()

        return jsonify({
            "documents": [
                {
                    "id": row["id"],
                    "owner_id": row["owner_id"],
                    "title": row["title"],
                    "category": row["category"],
                    "filename": row["original_filename"],
                    "content_type": row["content_type"],
                    "file_size": row["file_size"],
                    "sha256": row["sha256"],
                    "created_at": row["created_at"],
                    "access_level": row["access_level"],
                    "is_owner": int(row["owner_id"]) == int(user_id),
                }
                for row in rows
            ]
        })

    finally:
        connection.close()


# ---------------- DOWNLOAD DOCUMENT ----------------

@app.get("/api/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    user_id = int(session["user_id"])
    connection = get_db()

    try:
        document = connection.execute(
            """
            SELECT
                d.id,
                d.owner_id,
                d.original_filename,
                d.stored_filename
            FROM documents AS d
            WHERE d.id = ?
              AND (
                    d.owner_id = ?
                    OR EXISTS (
                        SELECT 1
                        FROM document_permissions AS p
                        WHERE p.document_id = d.id
                          AND p.user_id = ?
                          AND p.access_level IN ('read', 'edit')
                    )
              )
            """,
            (document_id, user_id, user_id),
        ).fetchone()

        if document is None:
            write_audit_log(
                connection,
                actor_id=user_id,
                action="document_download",
                outcome="denied",
                details={
                    "requested_document_id": document_id
                },
            )

            connection.commit()

            return error(
                "Document not found or you do not have permission to download it.",
                404,
            )

        storage_path = (
            STORAGE_DIR / document["stored_filename"]
        ).resolve()

        if storage_path.parent != STORAGE_DIR.resolve():
            write_audit_log(
                connection,
                actor_id=user_id,
                action="document_download",
                outcome="failure",
                document_id=document["id"],
                details={
                    "reason": "invalid_storage_path"
                },
            )

            connection.commit()

            return error("Invalid document storage path.", 400)

        if not storage_path.is_file():
            write_audit_log(
                connection,
                actor_id=user_id,
                action="document_download",
                outcome="failure",
                document_id=document["id"],
                details={
                    "reason": "stored_file_missing"
                },
            )

            connection.commit()

            return error("Stored document file not found.", 404)

        write_audit_log(
            connection,
            actor_id=user_id,
            action="document_download",
            outcome="success",
            document_id=document["id"],
            details={
                "filename": document["original_filename"]
            },
        )

        connection.commit()

        return send_file(
            storage_path,
            as_attachment=True,
            download_name=document["original_filename"],
            conditional=False,
            max_age=0,
        )

    finally:
        connection.close()


# ---------------- FILE SIZE ERROR ----------------

@app.errorhandler(413)
def file_too_large(_exception):
    return error(
        "Request is too large. Maximum upload size is 10 MB.",
        413,
    )


# ---------------- LIST DOCUMENT SHARES ----------------

@app.get("/api/documents/<int:document_id>/share")
@login_required
def list_document_shares(document_id):
    connection = get_db()
    actor_id = session["user_id"]

    try:
        document = connection.execute(
            "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, actor_id),
        ).fetchone()

        if document is None:
            return error("Document not found or you are not its owner.", 404)

        rows = connection.execute(
            """
            SELECT p.user_id, u.email, p.access_level, p.created_at
            FROM document_permissions AS p
            JOIN users AS u ON u.id = p.user_id
            WHERE p.document_id = ?
            ORDER BY p.created_at DESC, p.user_id
            """,
            (document_id,),
        ).fetchall()

        return jsonify({
            "shares": [
                {
                    "user_id": row["user_id"],
                    "email": row["email"],
                    "access_level": row["access_level"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        })
    finally:
        connection.close()


# ---------------- SHARE DOCUMENT ----------------

@app.post("/api/documents/<int:document_id>/share")
@csrf_protected
@login_required
def share_document(document_id):
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    access_level = data.get("access_level", "read")

    if not isinstance(email, str) or not email.strip():
        return error("A valid recipient email is required.", 400)

    email = email.strip().lower()

    if access_level not in {"read", "edit"}:
        return error("Access level must be 'read' or 'edit'.", 400)

    connection = get_db()
    actor_id = session["user_id"]

    try:
        document = connection.execute(
            "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, actor_id),
        ).fetchone()

        if document is None:
            return error("Document not found or you are not its owner.", 404)

        recipient = connection.execute(
            "SELECT id FROM users WHERE lower(email) = ?",
            (email,),
        ).fetchone()

        if recipient is None:
            return error("No registered user found with that email.", 404)

        if recipient["id"] == actor_id:
            return error("You cannot share a document with yourself.", 400)

        connection.execute(
            """
            INSERT INTO document_permissions
                (document_id, user_id, access_level, granted_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET
                access_level = excluded.access_level,
                granted_by = excluded.granted_by,
                created_at = CURRENT_TIMESTAMP
            """,
            (document_id, recipient["id"], access_level, actor_id),
        )

        write_audit_log(
            connection,
            actor_id=actor_id,
            action="document_share",
            outcome="success",
            document_id=document_id,
            target_user_id=recipient["id"],
            details={"access_level": access_level},
        )
        connection.commit()

        return jsonify({"message": "Document access updated successfully."}), 200

    except sqlite3.IntegrityError:
        connection.rollback()
        return error("Could not update document access.", 400)

    finally:
        connection.close()


# ---------------- REVOKE DOCUMENT ACCESS ----------------

@app.delete("/api/documents/<int:document_id>/share/<int:target_user_id>")
@csrf_protected
@login_required
def revoke_document_access(document_id, target_user_id):
    connection = get_db()
    actor_id = int(session["user_id"])

    try:
        document = connection.execute(
            "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, actor_id),
        ).fetchone()

        if document is None:
            return error("Document not found or you are not its owner.", 404)

        permission = connection.execute(
            """
            SELECT id FROM document_permissions
            WHERE document_id = ? AND user_id = ?
            """,
            (document_id, target_user_id),
        ).fetchone()

        if permission is None:
            return error("No sharing permission exists for this user.", 404)

        connection.execute(
            """
            DELETE FROM document_permissions
            WHERE document_id = ? AND user_id = ?
            """,
            (document_id, target_user_id),
        )

        write_audit_log(
            connection,
            actor_id=actor_id,
            action="document_share_revoked",
            outcome="success",
            document_id=document_id,
            target_user_id=target_user_id,
        )
        connection.commit()

        return jsonify({"message": "Document access revoked successfully."}), 200

    finally:
        connection.close()

# ---------------- AUDIT VERIFICATION ----------------

@app.get("/api/audit/verify")
@login_required
def audit_verify():
    connection = get_db()

    try:
        valid, failed_record_id = verify_audit_chain(connection)

        return jsonify({
            "valid": valid,
            "failed_record_id": failed_record_id,
            "message": (
                "Audit chain is valid."
                if valid
                else "Audit chain verification failed."
            ),
        }), 200 if valid else 409

    finally:
        connection.close()




# ---------------- RUN SERVER ----------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )

