
import { useEffect, useState } from "react";
import "./App.css";

const API = "http://localhost:5000";

function App() {
  const initialResetToken =
    new URLSearchParams(window.location.search).get("reset_token") || "";

  const [mode, setMode] = useState(initialResetToken ? "reset" : "login");
  const [resetToken, setResetToken] = useState(initialResetToken);
  const [backendStatus, setBackendStatus] = useState("Checking...");
  const [csrfToken, setCsrfToken] = useState("");
  const [user, setUser] = useState(null);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [documents, setDocuments] = useState([]);
  const [file, setFile] = useState(null);

  async function refreshCsrf() {
    const response = await fetch(`${API}/api/csrf`, {
      credentials: "include",
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Could not get security token.");
    }

    setCsrfToken(data.csrf_token);
    return data.csrf_token;
  }

  async function loadDocuments() {
    const response = await fetch(`${API}/api/documents`, {
      credentials: "include",
    });

    const data = await response.json();

    if (response.ok) {
      setDocuments(
        Array.isArray(data) ? data : data.documents || []
      );
    }
  }

  useEffect(() => {
    let active = true;

    async function initialise() {
      try {
        const health = await fetch(`${API}/api/health`, {
          credentials: "include",
        });

        if (!health.ok) {
          throw new Error("Backend unavailable");
        }

        if (active) setBackendStatus("Healthy");

        await refreshCsrf();

        const response = await fetch(`${API}/api/auth/me`, {
          credentials: "include",
        });

        if (response.ok) {
          const data = await response.json();

          if (active) setUser(data.user || data);

          await loadDocuments();
        }
      } catch {
        if (active) setBackendStatus("Not connected");
      }
    }

    initialise();

    return () => {
      active = false;
    };
  }, []);

  async function handleAuth(event) {
    event.preventDefault();
    setBusy(true);
    setMessage("");

    try {
      const token = csrfToken || await refreshCsrf();

      const body = mode === "register"
        ? { username, email, password }
        : { email, password };

      const response = await fetch(`${API}/api/auth/${mode}`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": token,
        },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Authentication failed.");
      }

      setUser(data.user);
      setCsrfToken(data.csrf_token || token);
      setPassword("");
      setMessage(
        mode === "register"
          ? "Account created successfully."
          : "Login successful."
      );

      await loadDocuments();
    } catch (error) {
      setMessage(error.message || "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  async function handleForgotPassword(event) {
    event.preventDefault();
    setMessage("");
    setBusy(true);

    try {
      const token = csrfToken || await refreshCsrf();

      const response = await fetch(
        `${API}/api/auth/forgot-password`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
          },
          body: JSON.stringify({ email }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Could not request a password reset."
        );
      }

      setMessage(data.message);
    } catch (error) {
      setMessage(
        error.message || "Password reset request failed."
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleResetPassword(event) {
    event.preventDefault();
    setMessage("");

    if (!resetToken) {
      setMessage("Reset link is missing. Request a new reset email.");
      return;
    }

    if (password !== confirmPassword) {
      setMessage("The passwords do not match.");
      return;
    }

    if (password.length < 12 || password.length > 128) {
      setMessage("Password must contain 12–128 characters.");
      return;
    }

    setBusy(true);

    try {
      const token = csrfToken || await refreshCsrf();

      const response = await fetch(
        `${API}/api/auth/reset-password`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
          },
          body: JSON.stringify({
            token: resetToken,
            password,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Password reset failed."
        );
      }

      setPassword("");
      setConfirmPassword("");
      setResetToken("");
      window.history.replaceState(
        {},
        document.title,
        window.location.pathname
      );
      setMode("login");
      setMessage(
        data.message ||
        "Password reset successful. Please sign in."
      );
    } catch (error) {
      setMessage(
        error.message || "Could not reset your password."
      );
    } finally {
      setBusy(false);
    }
  }

  function goToLogin() {
    setMode("login");
    setPassword("");
    setConfirmPassword("");
    setMessage("");
  }

  async function handleLogout() {
    setMessage("");
    setBusy(true);

    try {
      const token = csrfToken || await refreshCsrf();

      const response = await fetch(`${API}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: {
          "X-CSRF-Token": token,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Logout failed.");
      }

      setUser(null);
      setDocuments([]);
      setPassword("");
      await refreshCsrf();
      setMessage("You have logged out.");
    } catch (error) {
      setMessage(error.message || "Logout failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleUpload(event) {
    event.preventDefault();

    if (!file) {
      setMessage("Please choose a document first.");
      return;
    }

    setBusy(true);
    setMessage("");

    try {
      const token = csrfToken || await refreshCsrf();
      const formData = new FormData();

      formData.append("file", file);

      const response = await fetch(`${API}/api/documents`, {
        method: "POST",
        credentials: "include",
        headers: {
          "X-CSRF-Token": token,
        },
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Upload failed.");
      }

      setMessage("Document uploaded successfully.");
      setFile(null);
      await loadDocuments();
    } catch (error) {
      setMessage(error.message || "Upload failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload(documentId, filename) {
    setMessage("");

    try {
      const response = await fetch(
        `${API}/api/documents/${documentId}/download`,
        {
          credentials: "include",
        }
      );

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Download failed.");
      }

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = filename || "document";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setMessage(error.message || "Download failed.");
    }
  }

  const showAuthCard =
    !user || mode === "forgot" || mode === "reset";

  return (
    <main className="tv-page">
      <header className="tv-header">
        <div className="tv-brand">
          <div className="tv-logo">T</div>
          <div>
            <h1>TrustVault</h1>
            <p>Secure Document Management</p>
          </div>
        </div>

        <div className="tv-status">
          <span
            className={
              backendStatus === "Healthy"
                ? "status-dot online"
                : "status-dot"
            }
          />
          Backend: {backendStatus}
        </div>
      </header>

      <section className="tv-main">
        {showAuthCard ? (
          <div className="auth-layout">
            <div className="tv-intro">
              <span className="eyebrow">
                PRIVATE. PROTECTED. ORGANIZED.
              </span>

              <h2>
                Your important documents, protected in one place.
              </h2>

              <p>
                A secure workspace for storing and managing
                confidential files, with account-based access
                and activity auditing.
              </p>

              <div className="security-note">
                <span>◆</span>
                <div>
                  <strong>Security-first workspace</strong>
                  <p>
                    Protected sessions and server-side access checks.
                  </p>
                </div>
              </div>
            </div>

            <div className="auth-card">
              {(mode === "login" || mode === "register") && (
                <div className="auth-tabs">
                  <button
                    type="button"
                    className={mode === "login" ? "active" : ""}
                    onClick={() => {
                      setMode("login");
                      setMessage("");
                    }}
                  >
                    Sign in
                  </button>

                  <button
                    type="button"
                    className={mode === "register" ? "active" : ""}
                    onClick={() => {
                      setMode("register");
                      setMessage("");
                    }}
                  >
                    Create account
                  </button>
                </div>
              )}

              <h2>
                {mode === "login" && "Welcome back"}
                {mode === "register" && "Create your account"}
                {mode === "forgot" && "Forgot your password?"}
                {mode === "reset" && "Set a new password"}
              </h2>

              <p className="muted">
                {mode === "login" &&
                  "Sign in to access your secure workspace."}
                {mode === "register" &&
                  "Get started with your secure document workspace."}
                {mode === "forgot" &&
                  "Enter your registered email to receive a reset link."}
                {mode === "reset" &&
                  "Choose a new password for your TrustVault account."}
              </p>

              {mode === "login" || mode === "register" ? (
                <form onSubmit={handleAuth}>
                  {mode === "register" && (
                    <label>
                      Username
                      <input
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        minLength={3}
                        maxLength={30}
                        pattern="[A-Za-z0-9_]{3,30}"
                        required
                        placeholder="Choose a username"
                        autoComplete="username"
                      />
                    </label>
                  )}

                  <label>
                    Email address
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      placeholder="you@example.com"
                      autoComplete="email"
                    />
                  </label>

                  <label>
                    Password
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      minLength={12}
                      maxLength={128}
                      required
                      placeholder="At least 12 characters"
                      autoComplete={
                        mode === "login"
                          ? "current-password"
                          : "new-password"
                      }
                    />
                  </label>

                  {mode === "login" && (
                    <div className="forgot-password-row">
                      <button
                        type="button"
                        className="forgot-password-link"
                        onClick={() => {
                          setMessage("");
                          setMode("forgot");
                        }}
                      >
                        Forgot password?
                      </button>
                    </div>
                  )}

                  <button
                    className="primary-btn"
                    type="submit"
                    disabled={
                      busy || backendStatus !== "Healthy"
                    }
                  >
                    {busy
                      ? "Please wait..."
                      : mode === "login"
                        ? "Sign in securely"
                        : "Create account"}
                  </button>
                </form>
              ) : mode === "forgot" ? (
                <form onSubmit={handleForgotPassword}>
                  <label>
                    Email address
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      maxLength={254}
                      placeholder="you@example.com"
                      autoComplete="email"
                    />
                  </label>

                  <button
                    className="primary-btn"
                    type="submit"
                    disabled={
                      busy || backendStatus !== "Healthy"
                    }
                  >
                    {busy ? "Please wait..." : "Send reset link"}
                  </button>

                  <button
                    className="secondary-btn"
                    type="button"
                    onClick={goToLogin}
                    disabled={busy}
                  >
                    Back to sign in
                  </button>
                </form>
              ) : (
                <form onSubmit={handleResetPassword}>
                  <label>
                    New password
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      minLength={12}
                      maxLength={128}
                      required
                      placeholder="At least 12 characters"
                      autoComplete="new-password"
                    />
                  </label>

                  <label>
                    Confirm new password
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) =>
                        setConfirmPassword(e.target.value)
                      }
                      minLength={12}
                      maxLength={128}
                      required
                      placeholder="Enter the same password again"
                      autoComplete="new-password"
                    />
                  </label>

                  <button
                    className="primary-btn"
                    type="submit"
                    disabled={
                      busy ||
                      backendStatus !== "Healthy" ||
                      !resetToken
                    }
                  >
                    {busy ? "Please wait..." : "Reset password"}
                  </button>

                  {!resetToken && (
                    <p className="feedback" role="status">
                      Reset token is missing. Request a new reset link.
                    </p>
                  )}

                  <button
                    className="secondary-btn"
                    type="button"
                    onClick={goToLogin}
                    disabled={busy}
                  >
                    Back to sign in
                  </button>
                </form>
              )}

              {message && (
                <p className="feedback" role="status">
                  {message}
                </p>
              )}

              {(mode === "login" || mode === "register") && (
                <p className="form-foot">
                  Passwords must be at least 12 characters.
                </p>
              )}
            </div>
          </div>
        ) : (
          <div className="dashboard">
            <div className="dashboard-heading">
              <div>
                <span className="eyebrow">YOUR WORKSPACE</span>
                <h2>
                  Welcome{user.username ? `, ${user.username}` : ""}
                </h2>
                <p className="muted">
                  Manage your documents in one secure place.
                </p>
              </div>

              <button
                className="secondary-btn"
                onClick={handleLogout}
                disabled={busy}
              >
                Sign out
              </button>
            </div>

            <div className="dashboard-stats">
              <div className="stat-card">
                <span>ACCOUNT ROLE</span>
                <strong>{user.role || "User"}</strong>
              </div>

              <div className="stat-card">
                <span>DOCUMENTS</span>
                <strong>{documents.length}</strong>
              </div>

              <div className="stat-card">
                <span>BACKEND STATUS</span>
                <strong>{backendStatus}</strong>
              </div>
            </div>

            <div className="document-panel">
              <h3>Upload a document</h3>
              <p className="muted">
                Supported: PDF, TXT, DOC, DOCX, XLS, XLSX, PPT,
                PPTX. Maximum 10 MB.
              </p>

              <form
                className="upload-form"
                onSubmit={handleUpload}
              >
                <input
                  type="file"
                  accept=".pdf,.txt,.doc,.docx,.xls,.xlsx,.ppt,.pptx"
                  onChange={(e) =>
                    setFile(e.target.files?.[0] || null)
                  }
                />

                <button
                  className="primary-btn"
                  type="submit"
                  disabled={busy || !file}
                >
                  {busy ? "Please wait..." : "Upload file"}
                </button>
              </form>
            </div>

            <div className="document-panel">
              <h3>Your documents</h3>

              {documents.length === 0 ? (
                <p className="empty-state">
                  No documents to display yet. Upload your first
                  file above.
                </p>
              ) : (
                <div className="document-list">
                  {documents.map((doc) => (
                    <div className="document-row" key={doc.id}>
                      <div className="document-icon">FILE</div>

                      <div className="document-info">
                        <strong>
                          {doc.original_filename ||
                            doc.filename ||
                            doc.title ||
                            `Document ${doc.id}`}
                        </strong>
                        <span>
                          {doc.created_at || "Stored securely"}
                        </span>
                      </div>

                      <button
                        className="secondary-btn"
                        onClick={() =>
                          handleDownload(
                            doc.id,
                            doc.original_filename ||
                              doc.filename ||
                              "document"
                          )
                        }
                      >
                        Download
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {message && (
              <p className="feedback" role="status">
                {message}
              </p>
            )}
          </div>
        )}
      </section>

      <footer className="tv-footer">
        TrustVault · Secure Document Management
      </footer>
    </main>
  );
}

export default App;
