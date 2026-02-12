from __future__ import annotations

import hashlib
import html
import os
import secrets
import shutil
import sqlite3
import subprocess
from datetime import datetime, timedelta
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import cgi

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vault.db"
VAULT_DIR = BASE_DIR / "vault_storage"
HOST = "0.0.0.0"
PORT = 5000
SESSION_TTL_HOURS = 12


def utc_now() -> datetime:
    return datetime.utcnow()


def init_storage() -> None:
    VAULT_DIR.mkdir(exist_ok=True)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                passphrase TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                filename TEXT,
                status TEXT NOT NULL,
                ip_address TEXT,
                created_at TEXT NOT NULL
            )
            """
        )


def pbkdf2_hash(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200_000).hex()


def log_event(action: str, status: str, client_ip: str, user_id: int | None = None, username: str | None = None, filename: str | None = None) -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """
            INSERT INTO access_logs (user_id, username, action, filename, status, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, action, filename, status, client_ip, utc_now().isoformat(timespec="seconds")),
        )


def create_user(username: str, password: str) -> str | None:
    if len(username.strip()) < 3:
        return "Username must be at least 3 characters."
    if len(password) < 8:
        return "Password must be at least 8 characters."

    salt = secrets.token_hex(16)
    password_hash = pbkdf2_hash(password, salt)
    try:
        with sqlite3.connect(DB_PATH) as db:
            db.execute(
                "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (username.strip(), password_hash, salt, utc_now().isoformat(timespec="seconds")),
            )
    except sqlite3.IntegrityError:
        return "Username already exists."
    return None


def verify_user(username: str, password: str) -> sqlite3.Row | None:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        user = db.execute("SELECT id, username, password_hash, salt FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if not user:
        return None
    expected = pbkdf2_hash(password, user["salt"])
    return user if secrets.compare_digest(expected, user["password_hash"]) else None


def create_session(user_id: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = (utc_now() + timedelta(hours=SESSION_TTL_HOURS)).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as db:
        db.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", (token, user_id, expires_at))
    return token, expires_at


def get_current_user(cookie_header: str | None) -> sqlite3.Row | None:
    if not cookie_header:
        return None
    jar = cookies.SimpleCookie()
    jar.load(cookie_header)
    token = jar.get("session")
    if not token:
        return None

    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            """
            SELECT u.id, u.username, s.token, s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token.value,),
        ).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < utc_now():
            db.execute("DELETE FROM sessions WHERE token = ?", (token.value,))
            return None
        return row


def destroy_session(token: str) -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))


def encrypt_file(input_path: Path, output_path: Path, passphrase: str) -> None:
    env = os.environ.copy()
    env["ENC_PASSPHRASE"] = passphrase
    subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-salt",
            "-in",
            str(input_path),
            "-out",
            str(output_path),
            "-pass",
            "env:ENC_PASSPHRASE",
        ],
        check=True,
        env=env,
        capture_output=True,
    )


def decrypt_file(input_path: Path, output_path: Path, passphrase: str) -> None:
    env = os.environ.copy()
    env["ENC_PASSPHRASE"] = passphrase
    subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-in",
            str(input_path),
            "-out",
            str(output_path),
            "-pass",
            "env:ENC_PASSPHRASE",
        ],
        check=True,
        env=env,
        capture_output=True,
    )


def file_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def list_files(user_id: int) -> list[sqlite3.Row]:
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        return db.execute(
            "SELECT id, original_name, stored_name, sha256_hash, size_bytes, uploaded_at FROM files WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()


def render_layout(title: str, content: str, user: sqlite3.Row | None = None) -> str:
    auth_links = ""
    if user:
        auth_links = f"""
        <div class=\"userbar\">Logged in as <strong>{html.escape(user['username'])}</strong>
          <form method=\"post\" action=\"/logout\"><button class=\"secondary\" type=\"submit\">Logout</button></form>
        </div>
        """
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{html.escape(title)}</title>
  <link rel=\"stylesheet\" href=\"/static/styles.css\" />
</head>
<body>
  <main class=\"container\">
    <h1>Secure File Vault (AES)</h1>
    <p class=\"subtitle\">Encrypted storage, hashed credentials, access control, and file access logs.</p>
    {auth_links}
    {content}
  </main>
</body>
</html>"""


def render_auth_page(message: str = "") -> str:
    notice = f"<p class='notice'>{html.escape(message)}</p>" if message else ""
    return render_layout(
        "Secure File Vault",
        f"""
        {notice}
        <section class=\"grid\">
          <form class=\"panel\" method=\"post\" action=\"/register\">
            <h2>Create account</h2>
            <label>Username</label>
            <input type=\"text\" name=\"username\" required minlength=\"3\" />
            <label>Password</label>
            <input type=\"password\" name=\"password\" required minlength=\"8\" />
            <button type=\"submit\">Register</button>
          </form>
          <form class=\"panel\" method=\"post\" action=\"/login\">
            <h2>Login</h2>
            <label>Username</label>
            <input type=\"text\" name=\"username\" required />
            <label>Password</label>
            <input type=\"password\" name=\"password\" required />
            <button type=\"submit\">Login</button>
          </form>
        </section>
        """,
    )


def render_dashboard(user: sqlite3.Row, message: str = "") -> str:
    rows = list_files(user["id"])
    notice = f"<p class='notice'>{html.escape(message)}</p>" if message else ""
    file_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(r['original_name'])}</td>
          <td>{r['size_bytes']}</td>
          <td><code>{html.escape(r['sha256_hash'][:20])}...</code></td>
          <td>{html.escape(r['uploaded_at'])}</td>
          <td><a href=\"/download?id={r['id']}\">Download</a></td>
        </tr>
        """
        for r in rows
    )
    if not file_rows:
        file_rows = "<tr><td colspan='5'>No files uploaded yet.</td></tr>"

    return render_layout(
        "Vault Dashboard",
        f"""
        {notice}
        <section class=\"panel\">
          <h2>Upload file</h2>
          <form method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\">
            <input type=\"file\" name=\"vault_file\" required />
            <button type=\"submit\">Encrypt & Store</button>
          </form>
        </section>
        <section class=\"panel\">
          <h2>Your encrypted files</h2>
          <table>
            <thead><tr><th>Name</th><th>Bytes</th><th>SHA-256</th><th>Uploaded</th><th>Action</th></tr></thead>
            <tbody>{file_rows}</tbody>
          </table>
        </section>
        """,
        user,
    )


class AppHandler(BaseHTTPRequestHandler):
    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def _respond_html(self, html_content: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        payload = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self, location: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _serve_css(self) -> None:
        css = (BASE_DIR / "static" / "styles.css").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/css; charset=utf-8")
        self.send_header("Content-Length", str(len(css)))
        self.end_headers()
        self.wfile.write(css)

    def _current_user(self) -> sqlite3.Row | None:
        return get_current_user(self.headers.get("Cookie"))

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/static/styles.css":
            self._serve_css()
            return

        user = self._current_user()
        if parsed.path == "/":
            if user:
                self._respond_html(render_dashboard(user))
            else:
                self._respond_html(render_auth_page())
            return

        if parsed.path == "/download":
            if not user:
                log_event("DOWNLOAD", "DENIED", self._client_ip())
                self._redirect("/")
                return

            file_id = parse_qs(parsed.query).get("id", [""])[0]
            if not file_id.isdigit():
                self._respond_html(render_dashboard(user, "Invalid file id."), 400)
                return

            with sqlite3.connect(DB_PATH) as db:
                db.row_factory = sqlite3.Row
                row = db.execute(
                    "SELECT id, user_id, original_name, stored_name, passphrase, sha256_hash FROM files WHERE id = ?",
                    (int(file_id),),
                ).fetchone()

            if not row or row["user_id"] != user["id"]:
                log_event("DOWNLOAD", "DENIED", self._client_ip(), user["id"], user["username"], str(file_id))
                self._respond_html(render_dashboard(user, "Access denied."), 403)
                return

            encrypted_path = VAULT_DIR / row["stored_name"]
            temp_out = VAULT_DIR / f"tmp-{secrets.token_hex(8)}-{row['original_name']}"
            try:
                decrypt_file(encrypted_path, temp_out, row["passphrase"])
                if file_sha256(temp_out) != row["sha256_hash"]:
                    raise ValueError("Integrity check failed")
                data = temp_out.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f"attachment; filename={row['original_name']}")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                log_event("DOWNLOAD", "SUCCESS", self._client_ip(), user["id"], user["username"], row["original_name"])
            except Exception:
                log_event("DOWNLOAD", "FAILED", self._client_ip(), user["id"], user["username"], row["original_name"])
                self._respond_html(render_dashboard(user, "Download failed or integrity check mismatch."), 500)
            finally:
                if temp_out.exists():
                    temp_out.unlink()
            return

        self._respond_html("<h1>Not Found</h1>", 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        user = self._current_user()

        if parsed.path in {"/register", "/login", "/logout"}:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            form = parse_qs(body)

            if parsed.path == "/register":
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
                error = create_user(username, password)
                if error:
                    log_event("REGISTER", "FAILED", self._client_ip(), username=username)
                    self._respond_html(render_auth_page(error), 400)
                else:
                    log_event("REGISTER", "SUCCESS", self._client_ip(), username=username)
                    self._respond_html(render_auth_page("Registration successful. Please login."))
                return

            if parsed.path == "/login":
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
                found = verify_user(username, password)
                if not found:
                    log_event("LOGIN", "FAILED", self._client_ip(), username=username)
                    self._respond_html(render_auth_page("Invalid credentials."), 401)
                    return
                token, _ = create_session(found["id"])
                log_event("LOGIN", "SUCCESS", self._client_ip(), found["id"], found["username"])
                self._redirect("/", {"Set-Cookie": f"session={token}; HttpOnly; SameSite=Lax; Path=/"})
                return

            if parsed.path == "/logout":
                session_cookie = self.headers.get("Cookie", "")
                jar = cookies.SimpleCookie()
                jar.load(session_cookie)
                token = jar.get("session")
                if token:
                    destroy_session(token.value)
                if user:
                    log_event("LOGOUT", "SUCCESS", self._client_ip(), user["id"], user["username"])
                self._redirect("/", {"Set-Cookie": "session=deleted; Path=/; Max-Age=0"})
                return

        if parsed.path == "/upload":
            if not user:
                log_event("UPLOAD", "DENIED", self._client_ip())
                self._redirect("/")
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers.get("Content-Type", "")},
            )
            file_item = form["vault_file"] if "vault_file" in form else None
            if file_item is None or not getattr(file_item, "filename", ""):
                self._respond_html(render_dashboard(user, "No file selected."), 400)
                return

            safe_name = Path(file_item.filename).name
            temp_plain = VAULT_DIR / f"plain-{secrets.token_hex(8)}"
            with temp_plain.open("wb") as out:
                shutil.copyfileobj(file_item.file, out)

            stored_name = f"enc-{secrets.token_hex(12)}.bin"
            encrypted_path = VAULT_DIR / stored_name
            passphrase = secrets.token_urlsafe(32)
            sha = file_sha256(temp_plain)
            size_bytes = temp_plain.stat().st_size

            try:
                encrypt_file(temp_plain, encrypted_path, passphrase)
                with sqlite3.connect(DB_PATH) as db:
                    db.execute(
                        """
                        INSERT INTO files (user_id, original_name, stored_name, passphrase, sha256_hash, size_bytes, uploaded_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user["id"],
                            safe_name,
                            stored_name,
                            passphrase,
                            sha,
                            size_bytes,
                            utc_now().isoformat(timespec="seconds"),
                        ),
                    )
                log_event("UPLOAD", "SUCCESS", self._client_ip(), user["id"], user["username"], safe_name)
                self._respond_html(render_dashboard(user, "File encrypted and stored."))
            except Exception:
                log_event("UPLOAD", "FAILED", self._client_ip(), user["id"], user["username"], safe_name)
                self._respond_html(render_dashboard(user, "Upload failed."), 500)
            finally:
                if temp_plain.exists():
                    temp_plain.unlink()
            return

        self._respond_html("<h1>Not Found</h1>", 404)


def run() -> None:
    init_storage()
    init_db()
    server = HTTPServer((HOST, PORT), AppHandler)
    print(f"Server running at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
