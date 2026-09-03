from flask import Flask, jsonify, request, session, redirect
from pathlib import Path
import secrets
import base64
import sqlite3
import json
import time

from datetime import timedelta
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)

from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
BASE_DIR = Path(__file__).resolve().parent.parent

CERT_FILE = BASE_DIR / "192-168-1-69.sslip.io.pem"
KEY_FILE = BASE_DIR / "192-168-1-69.sslip.io-key.pem"
DB_FILE = Path(__file__).resolve().parent / "faceunlock.db"
PC_IDENTITY_FILE = Path(__file__).resolve().parent / "pc_identity.json"
SESSION_SECRET_FILE = Path(__file__).resolve().parent / "session_secret.txt"


def load_session_secret():

    if SESSION_SECRET_FILE.exists():

        with open(
            SESSION_SECRET_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            secret = file.read().strip()

        if secret:
            return secret

    secret = secrets.token_hex(32)

    with open(
        SESSION_SECRET_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(secret)

    return secret


app = Flask(__name__)

COMMAND_DISPATCH_TIMEOUT = 10
PENDING_COMMAND_TIMEOUT = 10
app.config["SECRET_KEY"] = load_session_secret()
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"


RP_ID = "192-168-1-69.sslip.io"
RP_NAME = "FaceUnlock"
ORIGIN = "https://192-168-1-69.sslip.io:5000"

registration_challenges = {}
authentication_challenges = {}
pairing_requests = {}
pairing_authentication_challenges = {}


def get_db():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection
def get_pc_identity():
    if not PC_IDENTITY_FILE.exists():
        raise FileNotFoundError("PC identity file not found.")

    with open(PC_IDENTITY_FILE, "r", encoding="utf-8") as file:
        identity = json.load(file)

    pc_id = identity.get("pc_id")

    if not pc_id:
        raise ValueError("PC identity is missing pc_id.")

    return pc_id
def is_registered_pc(pc_id):
    connection = get_db()

    row = connection.execute(
        """
        SELECT pc_id
        FROM pcs
        WHERE pc_id = ?
        """,
        (pc_id,)
    ).fetchone()

    connection.close()

    return row is not None
def is_credential_paired_with_pc(pc_id, credential_id):
    connection = get_db()

    row = connection.execute(
        """
        SELECT id
        FROM device_pairings
        WHERE pc_id = ? AND credential_id = ?
        """,
        (pc_id, credential_id)
    ).fetchone()

    connection.close()

    return row is not None
def get_authenticated_session():
    username = session.get("username")
    credential_id = session.get("credential_id")
    authenticated_at = session.get("authenticated_at")

    if not username or not credential_id or not authenticated_at:
        return None

    if time.time() - authenticated_at > 30 * 60:
        session.clear()
        return None

    return {
        "username": username,
        "credential_id": credential_id
    }
def get_pairing_request(pairing_token):
    pairing = pairing_requests.get(pairing_token)

    if pairing is None:
        return None

    if time.time() - pairing["created_at"] > 300:
        del pairing_requests[pairing_token]
        return None

    return pairing
def init_db():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            credential_public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL,
            credential_device_type TEXT,
            credential_backed_up INTEGER NOT NULL,
            user_verified INTEGER NOT NULL,
            transports TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS pcs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pc_id TEXT NOT NULL UNIQUE,
            pc_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen REAL,
            agent_secret TEXT
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS device_pairings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pc_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            paired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(pc_id, credential_id),
            FOREIGN KEY (pc_id) REFERENCES pcs(pc_id),
            FOREIGN KEY (credential_id) REFERENCES credentials(credential_id)
        )
        """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS agent_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pc_id TEXT NOT NULL,
            command TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            result TEXT,
            created_at REAL NOT NULL,
            dispatched_at REAL,
            completed_at REAL,
            FOREIGN KEY (pc_id) REFERENCES pcs(pc_id)
        )
    """)

    try:
        connection.execute(
            """
            ALTER TABLE agent_commands
            ADD COLUMN dispatched_at REAL
            """
        )
    except sqlite3.OperationalError as error:
        if "duplicate column name" not in str(error).lower():
            raise

    connection.commit()
    connection.close()
def register_local_pc():
    pc_id = get_pc_identity()

    connection = get_db()

    connection.execute(
        """
        INSERT OR IGNORE INTO pcs (pc_id, pc_name, last_seen)
        VALUES (?, ?, ?)
        """,
        (pc_id, "My Windows PC", time.time())
    )

    connection.commit()
    connection.close()

    return pc_id
def bytes_to_base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>FaceUnlock Stage 9</title>


        <style>

            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                min-height: 100vh;

                font-family:
                    Arial,
                    Helvetica,
                    sans-serif;

                background:
                    radial-gradient(
                        800px 500px at 50% -100px,
                        rgba(255, 255, 255, 0.06),
                        transparent 70%
                    ),
                    #080a0f;

                color: #f5f5f5;
            }

            .auth-page {
                min-height: 100vh;

                display: flex;
                align-items: center;
                justify-content: center;

                padding: 30px 20px;
            }

            .auth-card {
                width: 100%;
                max-width: 460px;

                padding: 40px;

                background: #101318;

                border: 1px solid #242932;

                border-radius: 18px;

                box-shadow:
                    0 25px 70px
                    rgba(0, 0, 0, 0.45);
            }

            /* Brand */

            .brand {
                display: flex;
                align-items: center;

                gap: 14px;

                margin-bottom: 32px;
            }

            .brand-icon {
                width: 50px;
                height: 50px;

                display: flex;
                align-items: center;
                justify-content: center;

                border-radius: 12px;

                background: #181c23;

                border: 1px solid #292f39;

                font-size: 23px;
            }

            .brand h1 {
                margin: 0;

                font-size: 24px;

                font-weight: 600;

                letter-spacing: -0.5px;
            }

            .brand p {
                margin: 4px 0 0;

                color: #858b96;

                font-size: 13px;
            }

            /* Authentication status */

            .auth-header {
                display: inline-flex;
                align-items: center;

                gap: 8px;

                padding: 7px 11px;

                margin-bottom: 20px;

                border-radius: 6px;

                background: #171b21;

                border: 1px solid #272d36;

                color: #aeb5c0;

                font-size: 11px;

                font-weight: 600;

                letter-spacing: 0.2px;
            }

            .security-dot {
                width: 6px;
                height: 6px;

                border-radius: 50%;

                background: #8b929d;
            }

            /* Heading */

            .auth-card h2 {
                margin: 0 0 10px;

                font-size: 30px;

                font-weight: 600;

                letter-spacing: -0.8px;
            }

            .description {
                margin: 0 0 28px;

                color: #858b96;

                font-size: 14px;

                line-height: 1.7;
            }

            /* Buttons */

            .auth-actions {
                display: flex;

                flex-direction: column;

                gap: 10px;
            }

            .auth-actions button {
                width: 100%;
                height: 52px;

                border-radius: 10px;

                font-family: inherit;

                font-size: 14px;

                font-weight: 600;

                cursor: pointer;

                transition:
                    background 0.2s ease,
                    border-color 0.2s ease,
                    transform 0.2s ease;
            }

            .auth-actions button:hover {
                transform: translateY(-1px);
            }

            .auth-actions button:active {
                transform: translateY(0);
            }

            .auth-actions button:disabled {
                opacity: 0.55;

                cursor: not-allowed;

                transform: none;
            }

            .primary-button {
                border: 1px solid #f1f1f1;

                background: #f1f1f1;

                color: #0b0d11;
            }

            .primary-button:hover {
                background: #ffffff;

                border-color: #ffffff;
            }

            .secondary-button {
                border: 1px solid #303640;

                background: #15181d;

                color: #d8dce2;
            }

            .secondary-button:hover {
                background: #1b1f25;

                border-color: #3a414c;
            }

            .auth-actions button span {
                margin-right: 7px;
            }

            /* Security information */

            .security-info {
                display: flex;

                flex-direction: column;

                gap: 14px;

                margin-top: 28px;

                padding-top: 24px;

                border-top: 1px solid #242932;
            }

            .security-item {
                display: flex;

                align-items: center;

                gap: 12px;
            }

            .security-item > span {
                width: 36px;
                height: 36px;

                display: flex;
                align-items: center;
                justify-content: center;

                flex-shrink: 0;

                border-radius: 9px;

                background: #181c22;

                border: 1px solid #292f38;

                font-size: 15px;
            }

            .security-item strong {
                display: block;

                margin-bottom: 2px;

                color: #dfe2e7;

                font-size: 13px;

                font-weight: 600;
            }

            .security-item p {
                margin: 0;

                color: #737a86;

                font-size: 11px;
            }

            /* Status */

            .status-message {
                min-height: 22px;

                margin-top: 22px;

                text-align: center;

                color: #8b929d;

                font-size: 13px;

                line-height: 1.5;
            }

            /* Footer */

            .footer {
                display: flex;

                justify-content: center;

                gap: 8px;

                margin-top: 24px;

                color: #555c68;

                font-size: 11px;
            }

            /* Mobile */

            @media (max-width: 520px) {

                .auth-page {
                    padding: 20px 14px;
                }

                .auth-card {
                    padding: 30px 22px;

                    border-radius: 16px;
                }

                .auth-card h2 {
                    font-size: 26px;
                }

                .brand h1 {
                    font-size: 22px;
                }

            }

        </style>


    </head>


    <body>

        <div class="auth-page">

            <div class="auth-card">

                <div class="brand">

                    <div class="brand-icon">
                        🔐
                    </div>

                    <div>

                        <h1>
                            FaceUnlock
                        </h1>

                        <p>
                            Secure Windows PC Control
                        </p>

                    </div>

                </div>


                <div class="auth-header">

                    <span class="security-dot"></span>

                    <span>
                        Secure Authentication
                    </span>

                </div>


                <h2>
                    Welcome back
                </h2>


                <p class="description">
                    Use your registered passkey to securely
                    authenticate and access your Windows PC.
                </p>


                <div class="auth-actions">

                    <button
                        class="primary-button"
                        onclick="authenticate()"
                    >

                        <span>🔓</span>

                        Authenticate

                    </button>


                    <button
                        class="secondary-button"
                        onclick="registerPasskey()"
                    >

                        <span>＋</span>

                        Register New Passkey

                    </button>

                </div>


                <div class="security-info">

                    <div class="security-item">

                        <span>
                            🛡️
                        </span>

                        <div>

                            <strong>
                                Passkey Protected
                            </strong>

                            <p>
                                No password is stored.
                            </p>

                        </div>

                    </div>


                    <div class="security-item">

                        <span>
                            🔒
                        </span>

                        <div>

                            <strong>
                                Encrypted Connection
                            </strong>

                            <p>
                                Communication is protected by HTTPS.
                            </p>

                        </div>

                    </div>

                </div>


                <div
                    id="status"
                    class="status-message"
                ></div>


                <div class="footer">

                    <span>
                        FaceUnlock
                    </span>

                    <span>
                        •
                    </span>

                    <span>
                        WebAuthn
                    </span>

                </div>

            </div>

        </div>

        <script>
            function base64urlToBuffer(value) {
                const padding = "=".repeat((4 - value.length % 4) % 4);
                const base64 = (value + padding)
                    .replace(/-/g, "+")
                    .replace(/_/g, "/");

                const binary = atob(base64);
                const bytes = new Uint8Array(binary.length);

                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }

                return bytes.buffer;
            }

            function bufferToBase64url(buffer) {
                const bytes = new Uint8Array(buffer);
                let binary = "";

                for (const byte of bytes) {
                    binary += String.fromCharCode(byte);
                }

                return btoa(binary)
                    .replace(/\\+/g, "-")
                    .replace(/\\//g, "_")
                    .replace(/=+$/, "");
            }
            async function checkSession() {

                    try {

                        const response =
                            await fetch("/session");

                        if (!response.ok) {
                            handleSessionExpired();
                            return false;
                        }

                        const data =
                            await response.json();

                        if (!data.authenticated) {
                            handleSessionExpired();
                            return false;
                        }

                        return true;

                    } catch (error) {

                        console.error(
                            "Session check failed:",
                            error
                        );

                        return false;
                    }
            }
            function handleSessionExpired() {

                setMessage(
                    "Your session has expired. Redirecting..."
                );

                setActivity(
                    "Authentication session expired."
                );

                setTimeout(() => {
                    window.location.href = "/";
                }, 1500);
            }



            async function registerPasskey() {
                const status = document.getElementById("status");

                try {
                    status.textContent = "Preparing registration...";

                    const response = await fetch("/register/options", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({
                            username: "rudra"
                        })
                    });

                    if (!response.ok) {
                        throw new Error("Could not get registration options.");
                    }

                    const options = await response.json();

                    options.challenge =
                        base64urlToBuffer(options.challenge);

                    options.user.id =
                        base64urlToBuffer(options.user.id);

                    if (options.excludeCredentials) {
                        options.excludeCredentials =
                            options.excludeCredentials.map(credential => ({
                                ...credential,
                                id: base64urlToBuffer(credential.id)
                            }));
                    }

                    status.textContent =
                        "Waiting for Face ID / fingerprint...";

                    const credential =
                        await navigator.credentials.create({
                            publicKey: options
                        });

                    if (!credential) {
                        throw new Error("No credential was created.");
                    }

                    const responseData = credential.response;

                    const credentialData = {
                        id: credential.id,
                        rawId: bufferToBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON:
                                bufferToBase64url(
                                    responseData.clientDataJSON
                                ),
                            attestationObject:
                                bufferToBase64url(
                                    responseData.attestationObject
                                ),
                            transports:
                                responseData.getTransports
                                    ? responseData.getTransports()
                                    : []
                        },
                        clientExtensionResults:
                            credential.getClientExtensionResults(),
                        authenticatorAttachment:
                            credential.authenticatorAttachment
                    };

                    status.textContent =
                        "Verifying registration...";

                    const verifyResponse =
                        await fetch("/register/verify", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({
                                username: "rudra",
                                credential: credentialData
                            })
                        });

                    const result = await verifyResponse.json();

                    if (!verifyResponse.ok) {
                        throw new Error(
                            result.error || "Registration failed."
                        );
                    }

                    status.textContent =
                        "Passkey registered and stored successfully.";

                } catch (error) {
                    console.error(error);
                    status.textContent =
                        "Error: " + error.message;
                }
            }

            async function authenticate() {
                const status = document.getElementById("status");

                try {
                    status.textContent =
                        "Preparing authentication...";

                    const response = await fetch("/login/options", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({
                            username: "rudra"
                        })
                    });

                    if (!response.ok) {
                        const result = await response.json();
                        throw new Error(
                            result.error || "Could not get authentication options."
                        );
                    }

                    const options = await response.json();

                    options.challenge =
                        base64urlToBuffer(options.challenge);

                    if (options.allowCredentials) {
                        options.allowCredentials =
                            options.allowCredentials.map(credential => ({
                                ...credential,
                                id: base64urlToBuffer(credential.id)
                            }));
                    }

                    status.textContent =
                        "Waiting for Face ID / fingerprint...";

                    const assertion =
                        await navigator.credentials.get({
                            publicKey: options
                        });

                    if (!assertion) {
                        throw new Error("No authentication response.");
                    }

                    const responseData = assertion.response;

                    const assertionData = {
                        id: assertion.id,
                        rawId: bufferToBase64url(assertion.rawId),
                        type: assertion.type,
                        response: {
                            clientDataJSON:
                                bufferToBase64url(
                                    responseData.clientDataJSON
                                ),
                            authenticatorData:
                                bufferToBase64url(
                                    responseData.authenticatorData
                                ),
                            signature:
                                bufferToBase64url(
                                    responseData.signature
                                ),
                            userHandle:
                                responseData.userHandle
                                    ? bufferToBase64url(
                                        responseData.userHandle
                                    )
                                    : null
                        },
                        clientExtensionResults:
                            assertion.getClientExtensionResults(),
                        authenticatorAttachment:
                            assertion.authenticatorAttachment
                    };

                    status.textContent =
                        "Verifying authentication...";

                    const verifyResponse =
                        await fetch("/login/verify", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({
                                username: "rudra",
                                credential: assertionData
                            })
                        });

                    const result = await verifyResponse.json();

                    if (!verifyResponse.ok) {
                        throw new Error(
                            result.error || "Authentication failed."
                        );
                    }

                    status.textContent =
                        "Authentication successful.";

                    window.location.href = "/dashboard";


                } catch (error) {
                    console.error(error);
                    status.textContent =
                        "Error: " + error.message;
                }
            }
        </script>
    </body>
    </html>
    """

@app.route("/dashboard")
def dashboard():
    authenticated = get_authenticated_session()

    if not authenticated:
        return redirect("/")

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >
        <title>FaceUnlock Dashboard</title>

        <style>

            * {
                margin: 0;
                box-sizing: border-box;
            }

            :root {
                --bg: #080a0f;

                --surface: #101318;
                --surface-2: #15181d;
                --surface-3: #181c22;

                --border: #242932;
                --border-light: #303640;

                --text: #f5f5f5;
                --text-soft: #d8dce2;
                --muted: #858b96;
                --muted-dark: #626975;

                --green: #34d399;
                --red: #fb7185;
                --yellow: #fbbf24;

                --blue: #60a5fa;
            }


            body {
                margin: 0;
                min-height: 100vh;

                font-family:
                    Inter,
                    -apple-system,
                    BlinkMacSystemFont,
                    "Segoe UI",
                    Arial,
                    sans-serif;

                background:
                    radial-gradient(
                        850px 500px at 50% -180px,
                        rgba(255, 255, 255, 0.055),
                        transparent 70%
                    ),
                    #080a0f;

                color: var(--text);

                padding: 40px 20px;
            }


            .container {
                width: 100%;
                max-width: 950px;

                margin: 0 auto;
            }


            /* Header */

            .header {
                position: relative;

                display: flex;
                justify-content: center;
                align-items: center;

                text-align: center;

                margin-bottom: 28px;
            }

            .header h1 {
                margin: 0;

                font-size: 36px;

                font-weight: 650;

                letter-spacing: -1px;
            }

            .header p {
                margin: 8px 0 0;

                color: var(--muted);

                font-size: 14px;
            }


            /* Logout */

            .logout-button {
                position: absolute;

                right: 0;
                top: 0;

                padding: 9px 14px;

                border: 1px solid var(--border-light);

                border-radius: 9px;

                background: var(--surface-2);

                color: #c9ced6;

                font-family: inherit;

                font-size: 12px;

                font-weight: 600;

                cursor: pointer;

                transition:
                    background 0.2s ease,
                    border-color 0.2s ease,
                    color 0.2s ease;
            }

            .logout-button:hover {
                background: var(--surface-3);

                border-color: #3a414c;

                color: #ffffff;
            }


            /* Cards */

            .card {
                position: relative;

                background: var(--surface);

                border: 1px solid var(--border);

                border-radius: 16px;

                padding: 24px;

                margin-bottom: 18px;

                box-shadow:
                    0 20px 50px
                    rgba(0, 0, 0, 0.28),

                    inset 0 1px 0
                    rgba(255, 255, 255, 0.025);
            }

            .card h2 {
                margin: 0 0 18px;

                font-size: 18px;

                font-weight: 600;

                letter-spacing: -0.2px;
            }


            /* Authentication */

            #authStatus {
                color: var(--green);

                font-weight: 600;
            }

            #username {
                color: var(--text);

                font-weight: 600;
            }


            /* PC Status */

            .status-row {
                display: flex;

                align-items: center;

                gap: 11px;

                margin: 15px 0;

                padding: 13px 14px;

                background: var(--surface-2);

                border: 1px solid var(--border);

                border-radius: 10px;
            }

            .indicator {
                width: 9px;
                height: 9px;

                flex-shrink: 0;

                border-radius: 50%;

                background: #68707c;
            }

            .indicator.online {
                background: var(--green);

                box-shadow:
                    0 0 0 4px
                    rgba(52, 211, 153, 0.08);
            }

            .indicator.offline {
                background: var(--red);

                box-shadow:
                    0 0 0 4px
                    rgba(251, 113, 133, 0.07);
            }

            #pcStatus {
                font-size: 13px;

                font-weight: 600;
            }


            /* PC Information */

            .info {
                color: var(--muted);

                font-size: 12px;

                margin-bottom: 20px;

                word-break: break-all;

                background: #0d1015;

                border: 1px solid var(--border);

                border-radius: 9px;

                padding: 11px 13px;

                line-height: 1.6;
            }

            #pcId {
                color: #b9bec7;

                font-family:
                    Consolas,
                    "Courier New",
                    monospace;

                font-size: 11px;
            }


            /* Buttons */

            .actions {
                display: flex;

                gap: 10px;

                flex-wrap: wrap;
            }

            button {
                border: 1px solid #e5e7eb;

                border-radius: 9px;

                padding: 11px 17px;

                font-family: inherit;

                font-size: 13px;

                font-weight: 600;

                cursor: pointer;

                background: #eeeeee;

                color: #0b0d11;

                transition:
                    background 0.2s ease,
                    border-color 0.2s ease,
                    transform 0.15s ease;
            }

            button:hover {
                background: #ffffff;

                border-color: #ffffff;

                transform: translateY(-1px);
            }

            button:active {
                transform: translateY(0);
            }

            button:disabled {
                opacity: 0.45;

                cursor: not-allowed;

                transform: none;
            }


            /* Lock button */

            button.lock {
                background: var(--surface-2);

                border-color: var(--border-light);

                color: #d8dce2;
            }

            button.lock:hover {
                background: var(--surface-3);

                border-color: #414854;

                color: #ffffff;
            }


            /* Authentication Button */

            #authButton {
                margin-top: 12px;

                background: #eeeeee;

                border-color: #eeeeee;

                color: #0b0d11;
            }

            #authButton:hover {
                background: #ffffff;

                border-color: #ffffff;
            }


            /* Message */

            #message {
                margin: 17px 0 0;

                min-height: 22px;

                color: var(--muted);

                font-size: 13px;

                line-height: 1.5;
            }


            /* Latest Activity */

            .activity {
                background: #0b0e13;

                border: 1px solid var(--border);

                border-radius: 10px;

                padding: 15px;

                font-family:
                    Consolas,
                    "Courier New",
                    monospace;

                font-size: 12px;

                line-height: 1.65;

                white-space: pre-wrap;

                word-break: break-word;

                min-height: 76px;

                color: #c7ccd4;

                overflow-x: auto;
            }


            /* Command History */

            .history {
                display: flex;

                flex-direction: column;

                gap: 9px;
            }

            .history-item {
                padding: 14px 15px;

                background: var(--surface-2);

                border: 1px solid var(--border);

                border-radius: 11px;

                transition:
                    border-color 0.2s ease,
                    background 0.2s ease;
            }

            .history-item:hover {
                border-color: #343a44;

                background: var(--surface-3);
            }


            .history-main {
                display: flex;

                justify-content: space-between;

                align-items: center;

                gap: 14px;
            }


            .history-command {
                display: flex;

                align-items: center;

                gap: 10px;

                font-weight: 600;

                font-size: 13px;
            }


            .history-icon {
                width: 32px;
                height: 32px;

                display: flex;

                align-items: center;
                justify-content: center;

                border-radius: 8px;

                background: #1a1e24;

                border: 1px solid #292f38;

                font-size: 14px;
            }


            .history-status {
                font-size: 10px;

                font-weight: 600;

                padding: 5px 8px;

                border-radius: 6px;

                text-transform: capitalize;

                border: 1px solid transparent;
            }


            .history-status.completed {
                color: #86efac;

                background: rgba(52, 211, 153, 0.07);

                border-color: rgba(52, 211, 153, 0.12);
            }


            .history-status.pending {
                color: #fcd34d;

                background: rgba(251, 191, 36, 0.07);

                border-color: rgba(251, 191, 36, 0.12);
            }


            .history-status.dispatched {
                color: #93c5fd;

                background: rgba(96, 165, 250, 0.07);

                border-color: rgba(96, 165, 250, 0.12);
            }


            .history-status.failed {
                color: #fda4af;

                background: rgba(251, 113, 133, 0.07);

                border-color: rgba(251, 113, 133, 0.12);
            }


            .history-details {
                display: flex;

                justify-content: space-between;

                align-items: center;

                gap: 15px;

                margin-top: 8px;

                padding-left: 42px;

                color: var(--muted-dark);

                font-size: 10px;
            }


            /* Mobile */

            @media (max-width: 650px) {

                body {
                    padding: 24px 14px;
                }

                .header {
                    justify-content: flex-start;

                    text-align: left;

                    padding-right: 90px;
                }

                .header h1 {
                    font-size: 27px;
                }

                .header p {
                    font-size: 13px;
                }

                .logout-button {
                    right: 0;
                    top: 0;
                }

                .card {
                    padding: 18px;

                    border-radius: 13px;
                }

                .history-main {
                    align-items: flex-start;
                }

                .history-details {
                    flex-direction: column;

                    align-items: flex-start;

                    gap: 4px;

                    padding-left: 42px;
                }

                .actions {
                    flex-direction: column;
                }

                .actions button {
                    width: 100%;
                }
            }

        </style>


    </head>

    <body>

        <div class="container">

            <div class="header">

                <div class="header-title">
                    <h1>FaceUnlock</h1>

                    <p>
                        Secure Windows PC Control Dashboard
                    </p>
                </div>

                <button
                    class="logout-button"
                    onclick="logout()"
                >
                    Logout
                </button>

            </div>


            <!-- Authentication -->

            <div class="card">

                <h2>Authentication</h2>

                <div class="status-row">

                    <span
                        id="authIndicator"
                        class="indicator"
                    ></span>

                    <span id="authStatus">
                        Checking authentication...
                    </span>

                    <button
                        id="authButton"
                        onclick="window.location.href='/'"
                        style="display: none;"
                    >
                        Go to Authentication
                    </button>

                </div>

                <p
                    id="username"
                    class="info"
                ></p>

            </div>


            <!-- Windows PC -->

            <div class="card">

                <h2>My Windows PC</h2>

                <div class="status-row">

                    <span
                        id="pcIndicator"
                        class="indicator"
                    ></span>

                    <span id="pcStatus">
                        Checking PC status...
                    </span>

                </div>

                <p class="info">
                    PC ID:
                    <span id="pcId">
                        Loading...
                    </span>
                </p>

                <div class="actions">

                    <button onclick="checkStatus()">
                        Check Status
                    </button>

                    <button
                        class="lock"
                        onclick="lockPC()"
                    >
                        Lock PC
                    </button>

                </div>

                <p id="message"></p>

            </div>


            <!-- Latest Activity -->

            <div class="card">

                <h2>Latest Activity</h2>

                <div
                    id="activity"
                    class="activity"
                >
                    No activity yet.
                </div>

            </div>


            <!-- Command History -->

            <div class="card">

                <h2>Command History</h2>

                <div
                    id="commandHistory"
                    class="history"
                >
                    Loading command history...
                </div>

            </div>

        </div>



        <script>

            const PC_ID =
                "18fbf0a0979ceeb4878f1ec80a29a02c";


            function setMessage(message) {
                document.getElementById(
                    "message"
                ).textContent = message;
            }


            function setActivity(data) {
                document.getElementById(
                    "activity"
                ).textContent =
                    JSON.stringify(data, null, 2);
            }

            async function checkSession() {

                try {

                    const response =
                        await fetch("/session");

                    if (!response.ok) {
                        handleSessionExpired();
                        return false;
                    }

                    const data =
                        await response.json();

                    if (!data.authenticated) {
                        handleSessionExpired();
                        return false;
                    }

                    return true;

                } catch (error) {

                    console.error(
                        "Session check failed:",
                        error
                    );

                    return false;
                }
            }


            function handleSessionExpired() {

                setMessage(
                    "Your session has expired. Redirecting..."
                );

                setActivity(
                    "Authentication session expired."
                );

                setTimeout(() => {
                    window.location.href = "/";
                }, 1500);
            }


            async function logout() {

                try {

                    const response =
                        await fetch(
                            "/logout",
                            {
                                method: "POST"
                            }
                        );

                    const data =
                        await response.json();

                    if (!response.ok) {
                        throw new Error(
                            data.error ||
                            "Logout failed."
                        );
                    }

                    window.location.href = "/";

                } catch (error) {

                    console.error(error);

                    setMessage(
                        error.message ||
                        "Logout failed."
                    );

                }
            }

            async function loadSession() {

                try {

                    const response =
                        await fetch("/session");

                    const data =
                        await response.json();

                    console.log("SESSION:", data);

                    if (!data.authenticated) {

                        handleSessionExpired();

                        return false;
                    }

                    document.getElementById(
                        "authIndicator"
                    ).className =
                        "indicator online";

                    document.getElementById(
                        "authStatus"
                    ).textContent =
                        "Authenticated";

                    document.getElementById(
                        "username"
                    ).textContent =
                        "User: " + data.username;

                    return true;

                } catch (error) {

                    console.error(
                        "Session error:",
                        error
                    );

                    handleSessionExpired();

                    return false;
                }
            }


            async function loadPCStatus() {

                try {

                    const response =
                        await fetch("/agent/status");

                    const data =
                        await response.json();

                    const indicator =
                        document.getElementById(
                            "pcIndicator"
                        );

                    const status =
                        document.getElementById(
                            "pcStatus"
                        );

                    const pcId =
                        document.getElementById(
                            "pcId"
                        );

                    pcId.textContent =
                        PC_ID;

                    if (!response.ok || !data.online) {

                        indicator.className =
                            "indicator offline";

                        status.textContent =
                            "Offline";

                        return;
                    }

                    indicator.className =
                        "indicator online";

                    status.textContent =
                        "Online";

                } catch (error) {

                    console.error(
                        "PC status error:",
                        error
                    );

                    document.getElementById(
                        "pcId"
                    ).textContent =
                        PC_ID;

                    document.getElementById(
                        "pcIndicator"
                    ).className =
                        "indicator offline";

                    document.getElementById(
                        "pcStatus"
                    ).textContent =
                        "Offline";
                }
            }


            async function checkStatus() {
                if (!(await checkSession())) {
                    return;
                }
                setMessage(
                    "Checking Windows PC..."
                );

                try {

                    const response =
                        await fetch("/remote/command", {
                            method: "POST",
                            headers: {
                                "Content-Type":
                                    "application/json"
                            },
                            body: JSON.stringify({
                                pc_id: PC_ID,
                                command: "status"
                            })
                        });

                    const data =
                        await response.json();

                    if (!response.ok) {
                        throw new Error(
                            data.error ||
                            "Could not queue command."
                        );
                    }

                    setMessage(
                        "Status command sent."
                    );

                    document.getElementById(
                        "pcId"
                    ).textContent = PC_ID;

                    await waitForResult(
                        data.command_id
                    );

                } catch (error) {

                    setMessage(
                        error.message
                    );
                }
            }
            async function loadCommandHistory() {

                try {

                    const response =
                        await fetch(
                            "/remote/commands?pc_id=" +
                            encodeURIComponent(PC_ID)
                        );

                    const data =
                        await response.json();

                    const history =
                        document.getElementById(
                            "commandHistory"
                        );

                    if (!response.ok) {
                        throw new Error(
                            data.error ||
                            "Could not load command history."
                        );
                    }

                    if (!data.commands ||
                        data.commands.length === 0) {

                        history.innerHTML =
                            "<p>No commands yet.</p>";

                        return;
                    }

                    history.innerHTML =
                        data.commands.map(command => {

                            const date =
                                new Date(
                                    command.created_at * 1000
                                );

                            let icon = "⚙️";

                            if (command.command === "status") {
                                icon = "📊";
                            }

                            if (command.command === "lock") {
                                icon = "🔒";
                            }

                            return `
                                <div class="history-item">

                                    <div class="history-main">

                                        <div class="history-command">

                                            <span class="history-icon">
                                                ${icon}
                                            </span>

                                            <span>
                                                ${
                                                    command.command
                                                        .charAt(0)
                                                        .toUpperCase() +
                                                    command.command
                                                        .slice(1)
                                                }
                                            </span>

                                        </div>

                                        <span
                                            class="history-status ${
                                                command.status
                                            }"
                                        >
                                            ${command.status}
                                        </span>

                                    </div>

                                    <div class="history-details">

                                        <span>
                                            Command #${command.id}
                                        </span>

                                        <span>
                                            ${date.toLocaleString()}
                                        </span>

                                    </div>

                                </div>
                            `;

                        }).join("");

                } catch (error) {

                    document.getElementById(
                        "commandHistory"
                    ).textContent =
                        error.message;
                }
            }
            async function lockPC() {

                if (!(await checkSession())) {
                    return;
                }

                const confirmed =
                    confirm(
                        "Are you sure you want to lock the Windows PC?"
                    );

                if (!confirmed) {
                    return;
                }

                setMessage(
                    "Sending lock command..."
                );

                try {

                    const response =
                        await fetch("/remote/command", {
                            method: "POST",
                            headers: {
                                "Content-Type":
                                    "application/json"
                            },
                            body: JSON.stringify({
                                pc_id: PC_ID,
                                command: "lock"
                            })
                        });

                    const data =
                        await response.json();

                    if (!response.ok) {
                        throw new Error(
                            data.error ||
                            "Could not queue lock command."
                        );
                    }

                    setMessage(
                        "Lock command sent."
                    );


                    await waitForResult(
                        data.command_id
                    );

                } catch (error) {

                    setMessage(
                        error.message
                    );
                }
            }



            async function waitForResult(
                commandId
            ) {

                for (
                    let attempt = 0;
                    attempt < 15;
                    attempt++
                ) {

                    await new Promise(
                        resolve =>
                            setTimeout(resolve, 1000)
                    );

                    try {

                        const response =
                            await fetch(
                                "/remote/command/result?pc_id=" +
                                encodeURIComponent(PC_ID) +
                                "&command_id=" +
                                encodeURIComponent(commandId)
                            );

                        const data =
                            await response.json();

                        if (
                            Number(data.command_id) !==
                            Number(commandId)
                        ) {
                            continue;
                        }

                        if (data.status === "completed") {

                            const commandName =
                                data.command === "lock"
                                    ? "Lock"
                                    : "Status";

                            const icon =
                                data.command === "lock"
                                    ? "🔒"
                                    : "📊";

                            const message =
                                data.result &&
                                data.result.message
                                    ? data.result.message
                                    : "Command completed successfully.";

                            document.getElementById(
                                "activity"
                            ).textContent =
                                `${icon} ${message}`;

                            document.getElementById(
                                "pcIndicator"
                            ).className =
                                "indicator online";

                            document.getElementById(
                                "pcStatus"
                            ).textContent =
                                "Online";

                            setMessage(
                                `${commandName} command completed successfully.`
                            );

                            return;
                        }

                        if (data.status === "failed") {

                            const commandName =
                                data.command === "lock"
                                    ? "Lock"
                                    : "Status";

                            const icon = "❌";

                            const errorMessage =
                                data.result &&
                                data.result.error
                                    ? data.result.error
                                    : "Command failed.";

                            document.getElementById(
                                "activity"
                            ).textContent =
                                `${icon} ${commandName} command failed: ${errorMessage}`;

                            setMessage(
                                `${commandName} command failed.`
                            );

                            return;
                        }

                    } catch (error) {

                        console.error(
                            error
                        );
                    }
                }

                setMessage(
                    "Command is still processing."
                );
            }

            window.addEventListener(
                "DOMContentLoaded",
                async () => {

                    const authenticated =
                        await loadSession();

                    if (!authenticated) {
                        return;
                    }

                    document.getElementById(
                        "pcId"
                    ).textContent =
                        PC_ID;

                    await loadPCStatus();

                    loadCommandHistory();
                }
            );

            setInterval(() => {
                loadPCStatus();
            }, 2000);

            setInterval(() => {
                loadCommandHistory();
            }, 2000);

            setInterval(async () => {

                const authenticated =
                    await checkSession();

                if (!authenticated) {
                    return;
                }

             }, 2000);

        </script>

    </body>
    </html>
    """
@app.route("/pair", methods=["GET"])
def pairing_page():
    return """
    <!DOCTYPE html>
    <html lang="en">

    <head>

        <meta charset="UTF-8">
        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>FaceUnlock - Pair Device</title>

        <style>

            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                min-height: 100vh;
                font-family: Arial, sans-serif;
                background:
                    radial-gradient(
                        circle at 50% 0%,
                        #1b2a44 0%,
                        #0d1420 42%,
                        #070b12 100%
                    );
                color: #ffffff;
            }

            .pair-page {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 30px 20px;
            }

            .pair-card {
                width: 100%;
                max-width: 460px;
                padding: 38px;
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 24px;
                background: rgba(17, 25, 39, 0.92);
                box-shadow:
                    0 30px 80px rgba(0, 0, 0, 0.45),
                    inset 0 1px 0 rgba(255, 255, 255, 0.04);
            }

            .brand {
                display: flex;
                align-items: center;
                gap: 14px;
                margin-bottom: 30px;
            }

            .brand-icon {
                width: 52px;
                height: 52px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 15px;
                background: #202d43;
                font-size: 24px;
            }

            .brand h1 {
                margin: 0;
                font-size: 24px;
                letter-spacing: -0.5px;
            }

            .brand p {
                margin: 4px 0 0;
                color: #8d99aa;
                font-size: 13px;
            }

            .pair-header {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 7px 12px;
                margin-bottom: 20px;
                border-radius: 999px;
                background: rgba(59, 130, 246, 0.08);
                color: #93c5fd;
                font-size: 12px;
                font-weight: 600;
            }

            .pair-dot {
                width: 7px;
                height: 7px;
                border-radius: 50%;
                background: #3b82f6;
                box-shadow:
                    0 0 10px rgba(59, 130, 246, 0.7);
            }

            .pair-card h2 {
                margin: 0 0 10px;
                font-size: 30px;
                letter-spacing: -0.8px;
            }

            .description {
                margin: 0 0 28px;
                color: #929daf;
                font-size: 14px;
                line-height: 1.7;
            }

            .pair-actions {
                display: flex;
                flex-direction: column;
                gap: 12px;
            }

            .pair-actions button {
                width: 100%;
                height: 52px;
                border-radius: 13px;
                font-family: inherit;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition:
                    transform 0.2s ease,
                    background 0.2s ease,
                    border-color 0.2s ease;
            }

            .pair-actions button:hover {
                transform: translateY(-1px);
            }

            .primary-button {
                border: 1px solid #ffffff;
                background: #ffffff;
                color: #101722;
            }

            .primary-button:hover {
                background: #e8edf3;
                border-color: #e8edf3;
            }

            .secondary-button {
                border: 1px solid rgba(255, 255, 255, 0.12);
                background: transparent;
                color: #dbe2ec;
            }

            .secondary-button:hover {
                background: rgba(255, 255, 255, 0.05);
                border-color: rgba(255, 255, 255, 0.2);
            }

            .pair-actions button span {
                margin-right: 7px;
            }

            .pair-info {
                display: flex;
                flex-direction: column;
                gap: 14px;
                margin-top: 28px;
                padding-top: 24px;
                border-top: 1px solid rgba(255, 255, 255, 0.07);
            }

            .pair-item {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .pair-item > span {
                width: 36px;
                height: 36px;
                display: flex;
                align-items: center;
                justify-content: center;
                flex-shrink: 0;
                border-radius: 10px;
                background: rgba(255, 255, 255, 0.05);
                font-size: 16px;
            }

            .pair-item strong {
                display: block;
                margin-bottom: 2px;
                font-size: 13px;
            }

            .pair-item p {
                margin: 0;
                color: #778296;
                font-size: 11px;
            }

            .status-message {
                min-height: 22px;
                margin-top: 22px;
                text-align: center;
                color: #9ca8b9;
                font-size: 13px;
                line-height: 1.5;
            }

            .footer {
                display: flex;
                justify-content: center;
                gap: 8px;
                margin-top: 24px;
                color: #586476;
                font-size: 11px;
            }

            @media (max-width: 520px) {

                .pair-page {
                    padding: 20px 14px;
                }

                .pair-card {
                    padding: 28px 22px;
                    border-radius: 20px;
                }

                .pair-card h2 {
                    font-size: 26px;
                }

                .brand h1 {
                    font-size: 22px;
                }

            }

        </style>

    </head>

    <body>

        <div class="pair-page">

            <div class="pair-card">

                <div class="brand">

                    <div class="brand-icon">
                        🔐
                    </div>

                    <div>
                        <h1>FaceUnlock</h1>

                        <p>
                            Secure Windows PC Control
                        </p>
                    </div>

                </div>


                <div class="pair-header">

                    <span class="pair-dot"></span>

                    <span>
                        Device Pairing
                    </span>

                </div>


                <h2>Pair this device</h2>

                <p class="description">
                    Connect this device to your Windows PC using
                    your registered passkey.
                </p>


                <div class="pair-actions">

                    <button
                        id="pairButton"
                        class="primary-button"
                        onclick="pairDevice()"
                    >
                        <span>🔗</span>
                        Pair This Device
                    </button>

                    <button
                        class="secondary-button"
                        onclick="window.location.href='/'"
                    >
                        <span>←</span>
                        Back to Authentication
                    </button>

                </div>


                <div class="pair-info">

                    <div class="pair-item">

                        <span>📱</span>

                        <div>

                            <strong>
                                Use your passkey
                            </strong>

                            <p>
                                Verify with Face ID, fingerprint,
                                or your device PIN.
                            </p>

                        </div>

                    </div>


                    <div class="pair-item">

                        <span>🔒</span>

                        <div>

                            <strong>
                                Secure pairing
                            </strong>

                            <p>
                                Only a registered passkey can
                                authorize this device.
                            </p>

                        </div>

                    </div>

                </div>


                <div
                    id="status"
                    class="status-message"
                ></div>


                <div class="footer">

                    <span>
                        FaceUnlock
                    </span>

                    <span>•</span>

                    <span>
                        WebAuthn
                    </span>

                </div>

            </div>

        </div>



        <script>
            function base64urlToBuffer(value) {
                const padding =
                    "=".repeat((4 - value.length % 4) % 4);

                const base64 = (value + padding)
                    .replace(/-/g, "+")
                    .replace(/_/g, "/");

                const binary = atob(base64);
                const bytes = new Uint8Array(binary.length);

                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }

                return bytes.buffer;
            }

            function bufferToBase64url(buffer) {
                const bytes = new Uint8Array(buffer);
                let binary = "";

                for (const byte of bytes) {
                    binary += String.fromCharCode(byte);
                }

                return btoa(binary)
                    .replace(/\\+/g, "-")
                    .replace(/\\//g, "_")
                    .replace(/=+$/, "");
            }

            function getPairingToken() {
                const params = new URLSearchParams(
                    window.location.search
                );

                return params.get("token");
            }

            async function pairDevice() {
                const button =
                    document.getElementById("pairButton");

                const status =
                    document.getElementById("status");

                const pairingToken =
                    getPairingToken();

                if (!pairingToken) {
                    status.className = "error";
                    status.textContent =
                        "Pairing token is missing.";
                    return;
                }

                button.disabled = true;

                try {
                    status.className = "";
                    status.textContent =
                        "Preparing secure pairing...";

                    const optionsResponse =
                        await fetch("/pair/auth/options", {
                            method: "POST",
                            headers: {
                                "Content-Type":
                                    "application/json"
                            },
                            body: JSON.stringify({
                                pairing_token:
                                    pairingToken
                            })
                        });

                    const optionsResult =
                        await optionsResponse.json();

                    if (!optionsResponse.ok) {
                        throw new Error(
                            optionsResult.error ||
                            "Could not start pairing."
                        );
                    }

                    const options = optionsResult;

                    options.challenge =
                        base64urlToBuffer(
                            options.challenge
                        );

                    if (options.allowCredentials) {
                        options.allowCredentials =
                            options.allowCredentials.map(
                                credential => ({
                                    ...credential,
                                    id:
                                        base64urlToBuffer(
                                            credential.id
                                        )
                                })
                            );
                    }

                    status.textContent =
                        "Waiting for Face ID / fingerprint...";

                    const assertion =
                        await navigator.credentials.get({
                            publicKey: options
                        });

                    if (!assertion) {
                        throw new Error(
                            "No authentication response."
                        );
                    }

                    const responseData =
                        assertion.response;

                    const assertionData = {
                        id: assertion.id,

                        rawId:
                            bufferToBase64url(
                                assertion.rawId
                            ),

                        type: assertion.type,

                        response: {
                            clientDataJSON:
                                bufferToBase64url(
                                    responseData.clientDataJSON
                                ),

                            authenticatorData:
                                bufferToBase64url(
                                    responseData.authenticatorData
                                ),

                            signature:
                                bufferToBase64url(
                                    responseData.signature
                                ),

                            userHandle:
                                responseData.userHandle
                                    ? bufferToBase64url(
                                        responseData.userHandle
                                    )
                                    : null
                        },

                        clientExtensionResults:
                            assertion
                                .getClientExtensionResults(),

                        authenticatorAttachment:
                            assertion
                                .authenticatorAttachment
                    };

                    status.textContent =
                        "Verifying secure pairing...";

                    const verifyResponse =
                        await fetch(
                            "/pair/auth/verify",
                            {
                                method: "POST",
                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },
                                body: JSON.stringify({
                                    pairing_token:
                                        pairingToken,
                                    credential:
                                        assertionData
                                })
                            }
                        );

                    const result =
                        await verifyResponse.json();

                    if (!verifyResponse.ok) {
                        throw new Error(
                            result.error ||
                            "Pairing failed."
                        );
                    }

                    status.className = "success";

                    status.textContent =
                        "Device paired successfully.";

                    button.textContent =
                        "Paired";

                } catch (error) {
                    console.error(error);

                    status.className = "error";

                    status.textContent =
                        "Error: " + error.message;

                    button.disabled = false;
                }
            }
        </script>

    </body>
    </html>
    """
@app.route("/session", methods=["GET"])
def get_session():
    authenticated = get_authenticated_session()

    if not authenticated:
        return jsonify({
            "authenticated": False
        }), 401

    return jsonify({
        "authenticated": True,
        "username": authenticated["username"],
        "credential_id": authenticated["credential_id"]
    })
@app.route("/pair/request", methods=["POST"])
def create_pairing_request():
    authenticated = get_authenticated_session()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    try:
        pc_id = get_pc_identity()
    except (FileNotFoundError, ValueError):
        return jsonify({
            "success": False,
            "error": "PC identity is not available."
        }), 500

    if not is_registered_pc(pc_id):
        return jsonify({
            "success": False,
            "error": "PC is not registered."
        }), 404

    pairing_token = secrets.token_urlsafe(32)

    pairing_requests[pairing_token] = {
        "pc_id": pc_id,
        "username": authenticated["username"],
        "credential_id": authenticated["credential_id"],
        "created_at": time.time()
    }

    return jsonify({
        "success": True,
        "pairing_token": pairing_token,
        "pc_id": pc_id,
        "expires_in": 300
    })

@app.route("/pair/auth/options", methods=["POST"])
def pairing_auth_options():
    data = request.get_json(silent=True) or {}

    pairing_token = data.get("pairing_token")

    if not isinstance(pairing_token, str) or not pairing_token:
        return jsonify({
            "success": False,
            "error": "Pairing token is required."
        }), 400

    pairing = get_pairing_request(pairing_token)

    if pairing is None:
        return jsonify({
            "success": False,
            "error": "Pairing request is invalid or expired."
        }), 400

    username = pairing.get("username")

    if not isinstance(username, str) or not username:
        return jsonify({
            "success": False,
            "error": "Pairing request is invalid."
        }), 400

    connection = get_db()

    rows = connection.execute(
        """
        SELECT credential_id
        FROM credentials
        WHERE username = ?
        """,
        (username,)
    ).fetchall()

    connection.close()

    if not rows:
        return jsonify({
            "success": False,
            "error": "No registered passkey found."
        }), 404

    challenge = secrets.token_bytes(32)

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64.urlsafe_b64decode(
                row["credential_id"] + "=" *
                (-len(row["credential_id"]) % 4)
            )
        )
        for row in rows
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=challenge,
        timeout=60000,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    pairing_authentication_challenges[pairing_token] = {
        "challenge": challenge,
        "created_at": time.time(),
        "username": username
    }

    return app.response_class(
        response=options_to_json(options),
        status=200,
        mimetype="application/json",
    )
@app.route("/pair/auth/verify", methods=["POST"])
def pairing_auth_verify():
    data = request.get_json(silent=True) or {}

    pairing_token = data.get("pairing_token")
    credential = data.get("credential")

    if not isinstance(pairing_token, str) or not pairing_token:
        return jsonify({
            "success": False,
            "error": "Pairing token is required."
        }), 400

    if not isinstance(credential, dict):
        return jsonify({
            "success": False,
            "error": "Credential is required."
        }), 400

    pairing = get_pairing_request(pairing_token)

    if pairing is None:
        return jsonify({
            "success": False,
            "error": "Pairing request is invalid or expired."
        }), 400

    authentication = pairing_authentication_challenges.get(
        pairing_token
    )

    if not authentication:
        return jsonify({
            "success": False,
            "error": "Pairing authentication session not found."
        }), 400

    if time.time() - authentication["created_at"] > 60:
        pairing_authentication_challenges.pop(
            pairing_token,
            None
        )

        return jsonify({
            "success": False,
            "error": "Pairing authentication session expired."
        }), 400

    challenge = authentication["challenge"]
    username = authentication["username"]

    credential_id = credential.get("id")

    if not isinstance(credential_id, str) or not credential_id:
        return jsonify({
            "success": False,
            "error": "Credential ID is missing."
        }), 400

    connection = get_db()

    stored = connection.execute(
        """
        SELECT *
        FROM credentials
        WHERE username = ?
          AND credential_id = ?
        """,
        (
            username,
            credential_id
        )
    ).fetchone()

    if not stored:
        connection.close()

        return jsonify({
            "success": False,
            "error": "Credential is not registered for this account."
        }), 401

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64.urlsafe_b64decode(
                stored["credential_public_key"] + "=" *
                (-len(stored["credential_public_key"]) % 4)
            ),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )

    except Exception:
        connection.close()

        return jsonify({
            "success": False,
            "error": "Pairing authentication failed."
        }), 401

    connection.execute(
        """
        UPDATE credentials
        SET sign_count = ?,
            user_verified = ?,
            credential_device_type = ?,
            credential_backed_up = ?
        WHERE credential_id = ?
        """,
        (
            verification.new_sign_count,
            int(verification.user_verified),
            str(verification.credential_device_type),
            int(verification.credential_backed_up),
            credential_id,
        )
    )

    try:
        connection.execute(
            """
            INSERT INTO device_pairings (
                pc_id,
                credential_id
            )
            VALUES (?, ?)
            """,
            (
                pairing["pc_id"],
                credential_id
            )
        )

        connection.commit()

    except sqlite3.IntegrityError:
        connection.rollback()
        connection.close()

        pairing_authentication_challenges.pop(
            pairing_token,
            None
        )

        pairing_requests.pop(
            pairing_token,
            None
        )

        return jsonify({
            "success": False,
            "error": "Device is already paired with this PC."
        }), 409

    connection.close()

    pairing_authentication_challenges.pop(
        pairing_token,
        None
    )

    pairing_requests.pop(
        pairing_token,
        None
    )

    return jsonify({
        "success": True,
        "message": "Device paired successfully.",
        "pc_id": pairing["pc_id"],
        "credential_id": credential_id,
        "username": stored["username"],
        "user_verified": verification.user_verified,
    })
@app.route("/agent/heartbeat", methods=["POST"])
def agent_heartbeat():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid request body."
        }), 400

    pc_id = data.get("pc_id")
    agent_secret = request.headers.get("X-Agent-Secret")

    if not isinstance(pc_id, str) or not pc_id.strip():
        return jsonify({
            "success": False,
            "error": "PC ID is required."
        }), 400

    if len(pc_id) > 100:
        return jsonify({
            "success": False,
            "error": "Invalid PC ID."
        }), 400

    if not isinstance(agent_secret, str) or not agent_secret:
        return jsonify({
            "success": False,
            "error": "Agent secret is required."
        }), 401

    if len(agent_secret) > 500:
        return jsonify({
            "success": False,
            "error": "Invalid agent secret."
        }), 401

    try:
        local_pc_id = get_pc_identity()
    except (FileNotFoundError, ValueError) as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500

    if pc_id != local_pc_id:
        return jsonify({
            "success": False,
            "error": "Unknown PC."
        }), 403

    connection = get_db()

    row = connection.execute(
        """
        SELECT agent_secret
        FROM pcs
        WHERE pc_id = ?
        """,
        (pc_id,)
    ).fetchone()

    if not row:
        connection.close()

        return jsonify({
            "success": False,
            "error": "PC is not registered."
        }), 404

    stored_secret = row["agent_secret"]

    if not stored_secret or agent_secret != stored_secret:
        connection.close()

        return jsonify({
            "success": False,
            "error": "Invalid agent secret."
        }), 401

    connection.execute(
        """
        UPDATE pcs
        SET last_seen = ?
        WHERE pc_id = ?
        """,
        (
            time.time(),
            pc_id
        )
    )

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "message": "Authenticated heartbeat accepted.",
        "pc_id": pc_id
    })
@app.route("/agent/status", methods=["GET"])
def agent_status():
    authenticated = get_authenticated_session()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    pc_id = get_pc_identity()

    if not is_credential_paired_with_pc(
        pc_id,
        authenticated["credential_id"]
    ):
        return jsonify({
            "success": False,
            "error": "This device is not paired with this PC."
        }), 403

    connection = get_db()

    row = connection.execute(
        """
        SELECT
            pc_id,
            pc_name,
            created_at,
            last_seen
        FROM pcs
        WHERE pc_id = ?
        """,
        (pc_id,)
    ).fetchone()

    connection.close()

    if not row:
        return jsonify({
            "success": False,
            "error": "PC not registered."
        }), 404

    last_seen = row["last_seen"]

    if last_seen is None:
        online = False
    else:
        online = time.time() - last_seen <= 30

    return jsonify({
        "success": True,
        "pc_id": row["pc_id"],
        "pc_name": row["pc_name"],
        "created_at": row["created_at"],
        "last_seen": last_seen,
        "online": online
    })
@app.route("/remote/command", methods=["POST"])
def remote_command():
    authenticated = get_authenticated_session()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid request body."
        }), 400

    pc_id = data.get("pc_id")
    command = data.get("command")

    if not isinstance(pc_id, str) or not pc_id.strip():
        return jsonify({
            "success": False,
            "error": "PC ID is required."
        }), 400

    if len(pc_id) > 100:
        return jsonify({
            "success": False,
            "error": "Invalid PC ID."
        }), 400

    if not isinstance(command, str) or not command.strip():
        return jsonify({
            "success": False,
            "error": "Command is required."
        }), 400

    if len(command) > 50:
        return jsonify({
            "success": False,
            "error": "Invalid command."
        }), 400

    credential_id = authenticated["credential_id"]

    if not is_credential_paired_with_pc(
        pc_id,
        credential_id
    ):
        return jsonify({
            "success": False,
            "error": "Device is not paired with this PC."
        }), 403

    if not is_registered_pc(pc_id):
        return jsonify({
            "success": False,
            "error": "PC is not registered."
        }), 404

    allowed_commands = {
        "status",
        "lock"
    }

    if command not in allowed_commands:
        return jsonify({
            "success": False,
            "error": "Command is not allowed."
        }), 400

    connection = get_db()
    current_time = time.time()
    pending_before = current_time - PENDING_COMMAND_TIMEOUT

    connection.execute(
        """
        UPDATE agent_commands
        SET
            status = 'failed',
            result = ?,
            completed_at = ?
        WHERE pc_id = ?
        AND status = 'pending'
        AND created_at < ?
        AND EXISTS (
            SELECT 1
            FROM pcs
            WHERE pcs.pc_id = agent_commands.pc_id
                AND (
                    pcs.last_seen IS NULL
                    OR ? - pcs.last_seen > 30
                )
        )
        """,
        (
            json.dumps({
                "success": False,
                "error": "Command timed out because the PC was offline."
            }),
            current_time,
            pc_id,
            pending_before,
            current_time
        )
    )

    connection.commit()
    cursor = connection.execute(
            """
            INSERT INTO agent_commands (
                pc_id,
                command,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                pc_id,
                command,
                "pending",
                time.time()
            )
        )

    command_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "pc_id": pc_id,
        "command": command,
        "command_id": command_id,
        "message": "Authorized command queued."
    })

@app.route("/remote/commands", methods=["GET"])
def get_command_history():
    authenticated = get_authenticated_session()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    pc_id = request.args.get("pc_id")

    if not pc_id:
        return jsonify({
            "success": False,
            "error": "PC ID is required."
        }), 400

    if not is_credential_paired_with_pc(
        pc_id,
        authenticated["credential_id"]
    ):
        return jsonify({
            "success": False,
            "error": "This device is not paired with the selected PC."
        }), 403

    connection = get_db()

    current_time = time.time()
    pending_before = current_time - PENDING_COMMAND_TIMEOUT

    pc_row = connection.execute(
        """
        SELECT last_seen
        FROM pcs
        WHERE pc_id = ?
        """,
        (pc_id,)
    ).fetchone()

    if pc_row:
        last_seen = pc_row["last_seen"]

        pc_offline = (
            last_seen is None
            or current_time - last_seen > 30
        )

        if pc_offline:
            connection.execute(
                """
                UPDATE agent_commands
                SET
                    status = 'failed',
                    result = ?,
                    completed_at = ?
                WHERE pc_id = ?
                  AND status = 'pending'
                  AND created_at < ?
                """,
                (
                    json.dumps({
                        "success": False,
                        "error": "Command timed out because the PC was offline."
                    }),
                    current_time,
                    pc_id,
                    pending_before
                )
            )

            connection.commit()

    rows = connection.execute(
        """
        SELECT
            id,
            pc_id,
            command,
            status,
            result,
            created_at,
            completed_at
        FROM agent_commands
        WHERE pc_id = ?
        ORDER BY created_at DESC
        LIMIT 20
        """,
        (pc_id,)
    ).fetchall()

    connection.close()

    commands = []

    for row in rows:
        command = dict(row)

        if command["result"]:
            try:
                command["result"] = json.loads(
                    command["result"]
                )
            except (TypeError, json.JSONDecodeError):
                pass

        commands.append(command)

    return jsonify({
        "success": True,
        "pc_id": pc_id,
        "commands": commands
    })

@app.route("/agent/command/poll", methods=["POST"])
def agent_command_poll():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid request body."
        }), 400

    pc_id = data.get("pc_id")
    agent_secret = request.headers.get("X-Agent-Secret")

    if not isinstance(pc_id, str) or not pc_id.strip():
        return jsonify({
            "success": False,
            "error": "PC ID is required."
        }), 400

    if len(pc_id) > 100:
        return jsonify({
            "success": False,
            "error": "Invalid PC ID."
        }), 400

    if not isinstance(agent_secret, str) or not agent_secret:
        return jsonify({
            "success": False,
            "error": "Agent secret is required."
        }), 401

    if len(agent_secret) > 500:
        return jsonify({
            "success": False,
            "error": "Invalid agent secret."
        }), 401

    connection = get_db()

    row = connection.execute(
        """
        SELECT agent_secret
        FROM pcs
        WHERE pc_id = ?
        """,
        (pc_id,)
    ).fetchone()

    if not row:
        connection.close()

        return jsonify({
            "success": False,
            "error": "PC is not registered."
        }), 404

    if not row["agent_secret"] or agent_secret != row["agent_secret"]:
        connection.close()

        return jsonify({
            "success": False,
            "error": "Invalid agent secret."
        }), 401
    current_time = time.time()

    pending_before = current_time - PENDING_COMMAND_TIMEOUT
    dispatched_before = current_time - COMMAND_DISPATCH_TIMEOUT

    connection.execute(
        """
        UPDATE agent_commands
        SET
            status = 'failed',
            result = ?,
            completed_at = ?
        WHERE pc_id = ?
        AND status = 'pending'
        AND created_at < ?
        """,
        (
            json.dumps({
                "success": False,
                "error": "Command timed out while the PC was offline."
            }),
            current_time,
            pc_id,
            pending_before
        )
    )

    connection.execute(
        """
        UPDATE agent_commands
        SET
            status = 'failed',
            result = ?,
            completed_at = ?
        WHERE pc_id = ?
        AND status = 'dispatched'
        AND dispatched_at IS NOT NULL
        AND dispatched_at < ?
        """,
        (
            json.dumps({
                "success": False,
                "error": "Command timed out while waiting for a result."
            }),
            current_time,
            pc_id,
            dispatched_before
        )
    )

    connection.commit()
    command_row = connection.execute(
            """
            SELECT id, command
            FROM agent_commands
            WHERE pc_id = ?
            AND status = 'pending'
            ORDER BY id ASC
            LIMIT 1
            """,
            (pc_id,)
        ).fetchone()

    if not command_row:
            connection.close()

            return jsonify({
                "success": True,
                "command": None
            })

    connection.execute(
            """
            UPDATE agent_commands
            SET
                status = 'dispatched',
                dispatched_at = ?
            WHERE id = ?
            AND pc_id = ?
            AND status = 'pending'
            """,
            (
                time.time(),
                command_row["id"],
                pc_id
            )
        )


    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "command_id": command_row["id"],
        "command": command_row["command"]
    })

@app.route("/remote/command/result", methods=["GET"])
def remote_command_result():
    authenticated = get_authenticated_session()

    if not authenticated:
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    pc_id = request.args.get("pc_id")
    command_id = request.args.get("command_id")

    if not pc_id:
        return jsonify({
            "success": False,
            "error": "PC ID is required."
        }), 400

    if not command_id:
        return jsonify({
            "success": False,
            "error": "Command ID is required."
        }), 400

    try:
        command_id = int(command_id)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "error": "Invalid command ID."
        }), 400

    if command_id <= 0:
        return jsonify({
            "success": False,
            "error": "Invalid command ID."
        }), 400

    credential_id = authenticated["credential_id"]

    if not is_credential_paired_with_pc(
        pc_id,
        credential_id
    ):
        return jsonify({
            "success": False,
            "error": "Device is not paired with this PC."
        }), 403

    connection = get_db()

    row = connection.execute(
        """
        SELECT
            id,
            pc_id,
            command,
            status,
            result,
            created_at,
            completed_at
        FROM agent_commands
        WHERE id = ?
          AND pc_id = ?
        """,
        (
            command_id,
            pc_id
        )
    ).fetchone()

    connection.close()

    if not row:
        return jsonify({
            "success": False,
            "error": "Command not found."
        }), 404

    result = None

    if row["result"]:
        try:
            result = json.loads(row["result"])
        except (TypeError, json.JSONDecodeError):
            result = row["result"]

    return jsonify({
        "success": True,
        "pc_id": row["pc_id"],
        "command_id": row["id"],
        "command": row["command"],
        "status": row["status"],
        "result": result,
        "created_at": row["created_at"],
        "completed_at": row["completed_at"]
    })


@app.route("/agent/command/result", methods=["POST"])
def agent_command_result():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid request body."
        }), 400

    pc_id = data.get("pc_id")
    command_id = data.get("command_id")
    result = data.get("result")
    agent_secret = request.headers.get("X-Agent-Secret")

    if not isinstance(pc_id, str) or not pc_id.strip():
        return jsonify({
            "success": False,
            "error": "PC ID is required."
        }), 400

    if not isinstance(command_id, int) or command_id <= 0:
        return jsonify({
            "success": False,
            "error": "Invalid command ID."
        }), 400

    if result is None:
        return jsonify({
            "success": False,
            "error": "Command result is required."
        }), 400

    if not isinstance(agent_secret, str) or not agent_secret:
        return jsonify({
            "success": False,
            "error": "Agent secret is required."
        }), 401

    connection = get_db()

    row = connection.execute(
        """
        SELECT agent_secret
        FROM pcs
        WHERE pc_id = ?
        """,
        (pc_id,)
    ).fetchone()

    if not row:
        connection.close()

        return jsonify({
            "success": False,
            "error": "PC is not registered."
        }), 404

    if not row["agent_secret"] or agent_secret != row["agent_secret"]:
        connection.close()

        return jsonify({
            "success": False,
            "error": "Invalid agent secret."
        }), 401

    command_row = connection.execute(
        """
        SELECT
            id,
            command,
            status
        FROM agent_commands
        WHERE id = ?
          AND pc_id = ?
        """,
        (
            command_id,
            pc_id
        )
    ).fetchone()

    if not command_row:
        connection.close()

        return jsonify({
            "success": False,
            "error": "Command not found."
        }), 404

    if command_row["status"] == "completed":
        connection.close()

        return jsonify({
            "success": False,
            "error": "Command has already been completed."
        }), 409

    if command_row["status"] != "dispatched":
        connection.close()

        return jsonify({
            "success": False,
            "error": "Command is not in a dispatchable state."
        }), 409

    connection.execute(
        """
        UPDATE agent_commands
        SET
            status = 'completed',
            result = ?,
            completed_at = ?
        WHERE id = ?
          AND pc_id = ?
          AND status = 'dispatched'
        """,
        (
            json.dumps(result),
            time.time(),
            command_id,
            pc_id
        )
    )

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "message": "Command result stored."
    })


@app.route("/register/options", methods=["POST"])
def register_options():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "rudra")

    user_id = secrets.token_bytes(32)
    challenge = secrets.token_bytes(32)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        challenge=challenge,
        timeout=60000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    registration_challenges[username] = {
        "challenge": challenge,
        "user_id": user_id,
    }

    return app.response_class(
        response=options_to_json(options),
        status=200,
        mimetype="application/json",
    )


@app.route("/register/verify", methods=["POST"])
def register_verify():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    credential = data.get("credential")

    if not username:
        return jsonify({
            "error": "Username is required."
        }), 400

    if not credential:
        return jsonify({
            "error": "Credential is required."
        }), 400

    registration = registration_challenges.get(username)

    if not registration:
        return jsonify({
            "error": "Registration session not found."
        }), 400

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=registration["challenge"],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )

        credential_id = bytes_to_base64url(
            verification.credential_id
        )

        connection = get_db()

        connection.execute(
            """
            INSERT INTO credentials (
                username,
                credential_id,
                credential_public_key,
                sign_count,
                credential_device_type,
                credential_backed_up,
                user_verified,
                transports
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                credential_id,
                bytes_to_base64url(
                    verification.credential_public_key
                ),
                verification.sign_count,
                str(verification.credential_device_type),
                int(verification.credential_backed_up),
                int(verification.user_verified),
                ",".join(
                    credential["response"].get("transports", [])
                ),
            ),
        )

        connection.commit()
        connection.close()

        del registration_challenges[username]

        print()
        print("============================================")
        print("       PASSKEY REGISTRATION VERIFIED")
        print("============================================")
        print(f"Username: {username}")
        print(f"Credential ID: {credential_id}")
        print(f"Sign count: {verification.sign_count}")
        print(f"User verified: {verification.user_verified}")
        print()

        return jsonify({
            "status": "verified",
            "message": "Passkey registered and stored successfully.",
            "credential_id": credential_id,
            "user_verified": verification.user_verified
        })

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "This passkey is already registered."
        }), 400

    except Exception as error:
        print()
        print("[ERROR] WebAuthn registration verification failed.")
        print(error)
        print()

        return jsonify({
            "error": str(error)
        }), 400


@app.route("/login/options", methods=["POST"])
def login_options():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "rudra")

    connection = get_db()

    rows = connection.execute(
        """
        SELECT credential_id
        FROM credentials
        WHERE username = ?
        """,
        (username,)
    ).fetchall()

    connection.close()

    if not rows:
        return jsonify({
            "error": "No registered passkey found."
        }), 404

    challenge = secrets.token_bytes(32)

    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64.urlsafe_b64decode(
                row["credential_id"] + "=" *
                (-len(row["credential_id"]) % 4)
            )
        )
        for row in rows
    ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=challenge,
        timeout=60000,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    authentication_challenges[username] = challenge

    return app.response_class(
        response=options_to_json(options),
        status=200,
        mimetype="application/json",
    )


@app.route("/login/verify", methods=["POST"])
def login_verify():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    credential = data.get("credential")

    if not username:
        return jsonify({
            "error": "Username is required."
        }), 400

    if not credential:
        return jsonify({
            "error": "Credential is required."
        }), 400

    challenge = authentication_challenges.get(username)

    if not challenge:
        return jsonify({
            "error": "Authentication session not found."
        }), 400

    credential_id = credential.get("id")

    if not credential_id:
        return jsonify({
            "error": "Credential ID is missing."
        }), 400

    connection = get_db()

    stored = connection.execute(
        """
        SELECT *
        FROM credentials
        WHERE username = ? AND credential_id = ?
        """,
        (username, credential_id)
    ).fetchone()

    connection.close()

    if not stored:
        return jsonify({
            "error": "Credential is not registered."
        }), 401

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64.urlsafe_b64decode(
                stored["credential_public_key"] + "=" *
                (-len(stored["credential_public_key"]) % 4)
            ),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )

        connection = get_db()

        connection.execute(
            """
            UPDATE credentials
            SET sign_count = ?,
                user_verified = ?,
                credential_device_type = ?,
                credential_backed_up = ?
            WHERE credential_id = ?
            """,
            (
                verification.new_sign_count,
                int(verification.user_verified),
                str(verification.credential_device_type),
                int(verification.credential_backed_up),
                credential_id,
            )
        )

        connection.commit()
        connection.close()
        session.permanent = True

        session["username"] = username
        session["credential_id"] = credential_id
        session["authenticated_at"] = time.time()
        del authentication_challenges[username]

        print()
        print("============================================")
        print("       PASSKEY AUTHENTICATION SUCCESS")
        print("============================================")
        print(f"Username: {username}")
        print(f"Credential ID: {credential_id}")
        print(f"New sign count: {verification.new_sign_count}")
        print(f"User verified: {verification.user_verified}")
        print()

        return jsonify({
            "status": "authenticated",
            "message": "Authentication successful.",
            "user_verified": verification.user_verified,
            "new_sign_count": verification.new_sign_count
        })

    except Exception as error:
        print()
        print("[ERROR] WebAuthn authentication failed.")
        print(error)
        print()

        return jsonify({
            "error": "Authentication Failed"
        }), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    })
@app.route("/credentials", methods=["GET"])
def list_credentials():
    connection = get_db()

    rows = connection.execute(
        """
        SELECT
            username,
            credential_id,
            sign_count,
            credential_device_type,
            credential_backed_up,
            user_verified,
            transports,
            created_at
        FROM credentials
        ORDER BY id
        """
    ).fetchall()

    connection.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


if __name__ == "__main__":
    init_db()

    print("============================================")
    print("       FaceUnlock Stage 9 Server")
    print("============================================")
    print()

    print("[1] Checking certificate files...")
    print(f"Certificate: {CERT_FILE}")
    print(f"Private key: {KEY_FILE}")
    print(f"Database: {DB_FILE}")

    if not CERT_FILE.exists():
        print("[ERROR] Certificate file not found.")
        exit(1)

    if not KEY_FILE.exists():
        print("[ERROR] Private key file not found.")
        exit(1)

    print("[OK] Certificate found.")
    print("[OK] Private key found.")
    print("[OK] Database ready.")
    print()

    print("[2] Starting HTTPS server...")
    print(f"PC: {ORIGIN}")
    print()
    pc_id = register_local_pc()
    print(f"PC ID: {pc_id}")
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=(str(CERT_FILE), str(KEY_FILE))
    )