from flask import Flask, jsonify, request
from pathlib import Path
import secrets
import base64
import sqlite3

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

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

CERT_FILE = BASE_DIR / "192-168-1-69.sslip.io.pem"
KEY_FILE = BASE_DIR / "192-168-1-69.sslip.io-key.pem"
DB_FILE = Path(__file__).resolve().parent / "faceunlock.db"

RP_ID = "192-168-1-69.sslip.io"
RP_NAME = "FaceUnlock"
ORIGIN = "https://192-168-1-69.sslip.io:5000"

registration_challenges = {}
authentication_challenges = {}


def get_db():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


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

    connection.commit()
    connection.close()


def bytes_to_base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FaceUnlock Stage 9</title>
    </head>
    <body>
        <h1>FaceUnlock Stage 9</h1>

        <p>WebAuthn authentication is ready.</p>

        <button onclick="registerPasskey()">Register Passkey</button>
        <button onclick="authenticate()">Authenticate</button>

        <p id="status"></p>

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
            "error": str(error)
        }), 401


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

    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=(str(CERT_FILE), str(KEY_FILE))
    )