
from flask import Flask, jsonify, render_template_string, request
import base64
import json
import os
import secrets

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)

from webauthn.helpers import options_to_json

from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

app = Flask(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

RP_ID = "192-168-1-69.sslip.io"
RP_NAME = "FaceUnlock"

ORIGIN = "https://192-168-1-69.sslip.io:5443"

USER_ID = b"faceunlock-user-001"
USER_NAME = "rudra"
USER_DISPLAY_NAME = "Rudra"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIAL_FILE = os.path.join(BASE_DIR, "credential.json")


# ============================================================
# RUNTIME VARIABLES
# ============================================================

registration_challenge = None
authentication_challenge = None

credential = None


# ============================================================
# BASE64URL HELPERS
# ============================================================

def bytes_to_base64url(value):
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def base64url_to_bytes(value):
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


# ============================================================
# CREDENTIAL STORAGE
# ============================================================

def save_credential(data):
    with open(CREDENTIAL_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def load_credential():

    if not os.path.exists(CREDENTIAL_FILE):
        return None

    try:

        with open(CREDENTIAL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Convert stored Base64URL strings back to bytes
        data["credential_id"] = base64url_to_bytes(
            data["credential_id"]
        )

        # public_key was saved using normal Base64
        data["public_key"] = base64.b64decode(
            data["public_key"]
        )

        data["sign_count"] = int(
            data.get("sign_count", 0)
        )

        print("===================================")
        print(" Credential loaded from disk")
        print(" User:", data.get("user"))
        print("===================================")

        return data

    except Exception as e:

        print("Credential loading error:")
        print(type(e).__name__)
        print(e)

        return None


credential = load_credential()


# ============================================================
# HTML
# ============================================================

HTML = """
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0">

<title>FaceUnlock</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    display: flex;

    justify-content: center;

    align-items: center;

    background:
        linear-gradient(
            135deg,
            #08080b,
            #111118
        );

    color: white;

    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    padding: 24px;
}

.container {

    width: 100%;

    max-width: 430px;

    text-align: center;
}

.icon {

    font-size: 70px;

    margin-bottom: 18px;
}

h1 {

    margin: 0;

    font-size: 34px;

    font-weight: 700;
}

#description {

    color: #a9a9b0;

    line-height: 1.5;

    margin: 14px 0 28px;

    white-space: pre-line;
}

button {

    width: 100%;

    padding: 17px;

    border: none;

    border-radius: 14px;

    background: #007aff;

    color: white;

    font-size: 18px;

    font-weight: 600;

    cursor: pointer;

    transition: 0.2s;
}

button:active {

    transform: scale(0.98);
}

button:disabled {

    opacity: 0.5;

    cursor: not-allowed;
}

#result {

    margin-top: 22px;

    padding: 16px;

    border-radius: 12px;

    background: #19191f;

    color: #ddd;

    min-height: 52px;

    white-space: pre-wrap;

    word-break: break-word;

    text-align: left;
}

.success {

    color: #42d96b;
}

.error {

    color: #ff5c5c;
}

</style>

</head>


<body>


<div class="container">

    <div class="icon">
        🔐
    </div>

    <h1>
        FaceUnlock
    </h1>

    <p id="description">
        Checking Acer...
    </p>

    <button
        id="actionButton"
        type="button"
        disabled>

        Loading...

    </button>

    <div id="result">
        Connecting to Acer...
    </div>

</div>


<script>


// ============================================================
// GLOBAL
// ============================================================

let isRegistered = false;


// ============================================================
// BASE64URL → ARRAYBUFFER
// ============================================================

function base64urlToBuffer(base64url) {

    const padding =
        "=".repeat(
            (4 - base64url.length % 4) % 4
        );

    const base64 =
        (base64url + padding)
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const raw =
        atob(base64);

    const bytes =
        new Uint8Array(raw.length);

    for (
        let i = 0;
        i < raw.length;
        i++
    ) {

        bytes[i] =
            raw.charCodeAt(i);
    }

    return bytes.buffer;
}


// ============================================================
// ARRAYBUFFER → BASE64URL
// ============================================================

function bufferToBase64url(buffer) {

    const bytes =
        new Uint8Array(buffer);

    let binary = "";

    for (
        let i = 0;
        i < bytes.length;
        i++
    ) {

        binary +=
            String.fromCharCode(
                bytes[i]
            );
    }

    return btoa(binary)
        .replace(/\\+/g, "-")
        .replace(/\\//g, "_")
        .replace(/=/g, "");
}


// ============================================================
// PAGE SETUP
// ============================================================

async function setupPage() {

    const button =
        document.getElementById(
            "actionButton"
        );

    const description =
        document.getElementById(
            "description"
        );

    const result =
        document.getElementById(
            "result"
        );

    try {

        const response =
            await fetch(
                "/status",
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {

            throw new Error(
                "Server returned " +
                response.status
            );
        }

        const data =
            await response.json();

        isRegistered =
            data.iphone_registered;


        if (isRegistered) {

            description.innerText =
                "Your iPhone is registered with this Acer.\\n\\nUse Face ID to authenticate.";

            button.innerText =
                "🔐 Authenticate with Face ID";

        }

        else {

            description.innerText =
                "Register this iPhone with your Acer.\\n\\nFace ID will protect the credential.";

            button.innerText =
                "🔐 Register iPhone with Face ID";
        }


        result.innerText =
            "Ready.";

        button.disabled =
            false;


    }

    catch (error) {

        console.error(
            "Setup error:",
            error
        );

        description.innerText =
            "Could not connect to Acer.";

        result.innerText =
            "❌ " +
            error.message;

        button.innerText =
            "Retry";

        button.disabled =
            false;
    }
}


// ============================================================
// BUTTON
// ============================================================

document
    .getElementById("actionButton")
    .addEventListener(
        "click",
        async function() {

            if (isRegistered) {

                await authenticateIPhone();

            }

            else {

                await registerIPhone();

            }

        }
    );


// ============================================================
// REGISTER IPHONE
// ============================================================

async function registerIPhone() {

    const button =
        document.getElementById(
            "actionButton"
        );

    const result =
        document.getElementById(
            "result"
        );

    button.disabled =
        true;

    result.innerText =
        "Preparing Face ID registration...";


    try {

        // ----------------------------------------------------
        // Get registration options
        // ----------------------------------------------------

        const response =
            await fetch(
                "/register/options",
                {
                    cache: "no-store"
                }
            );


        const options =
            await response.json();


        if (!response.ok) {

            throw new Error(
                options.error ||
                "Failed to get registration options"
            );
        }


        // ----------------------------------------------------
        // Convert challenge
        // ----------------------------------------------------

        options.challenge =
            base64urlToBuffer(
                options.challenge
            );


        // ----------------------------------------------------
        // Convert user ID
        // ----------------------------------------------------

        options.user.id =
            base64urlToBuffer(
                options.user.id
            );


        // ----------------------------------------------------
        // Convert excluded credential IDs
        // ----------------------------------------------------

        if (
            options.excludeCredentials
        ) {

            options.excludeCredentials =
                options.excludeCredentials.map(
                    item => ({

                        ...item,

                        id:
                            base64urlToBuffer(
                                item.id
                            )

                    })
                );
        }


        // ----------------------------------------------------
        // Ask iPhone for Face ID
        // ----------------------------------------------------

        result.innerText =
            "Look at your iPhone for Face ID...";


        const newCredential =
            await navigator.credentials.create({

                publicKey:
                    options

            });


        if (!newCredential) {

            throw new Error(
                "No credential was created."
            );
        }


        // ----------------------------------------------------
        // Prepare credential for Flask
        // ----------------------------------------------------

        const responseData = {

            id:
                newCredential.id,

            rawId:
                bufferToBase64url(
                    newCredential.rawId
                ),

            type:
                newCredential.type,

            response: {

                clientDataJSON:
                    bufferToBase64url(
                        newCredential.response
                            .clientDataJSON
                    ),

                attestationObject:
                    bufferToBase64url(
                        newCredential.response
                            .attestationObject
                    )
            }
        };


        result.innerText =
            "Sending credential to Acer...";


        // ----------------------------------------------------
        // Verify registration
        // ----------------------------------------------------

        const verifyResponse =
            await fetch(
                "/register/verify",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify(
                            responseData
                        )

                }
            );


        const verification =
            await verifyResponse.json();


        if (!verifyResponse.ok) {

            throw new Error(
                verification.error ||
                "Registration verification failed."
            );
        }


        // ----------------------------------------------------
        // Success
        // ----------------------------------------------------

        isRegistered =
            true;


        document.getElementById(
            "description"
        ).innerText =
            "Your iPhone is registered with this Acer.\\n\\nUse Face ID to authenticate.";


        button.innerText =
            "🔐 Authenticate with Face ID";


        result.innerText =
            "✅ iPhone registered successfully!\\n\\n" +
            "Face ID credential has been saved on Acer.";

        result.className =
            "success";


    }

    catch (error) {

        console.error(
            "Registration error:",
            error
        );

        result.innerText =
            "❌ Registration failed\\n\\n" +
            error.message;

        result.className =
            "error";
    }


    finally {

        button.disabled =
            false;
    }
}


// ============================================================
// AUTHENTICATE IPHONE
// ============================================================

async function authenticateIPhone() {

    const button =
        document.getElementById(
            "actionButton"
        );

    const result =
        document.getElementById(
            "result"
        );

    button.disabled =
        true;

    result.innerText =
        "Preparing authentication...";


    try {

        // ----------------------------------------------------
        // Get authentication options
        // ----------------------------------------------------

        const response =
            await fetch(
                "/authenticate/options",
                {
                    cache: "no-store"
                }
            );


        const options =
            await response.json();


        if (!response.ok) {

            throw new Error(
                options.error ||
                "Failed to get authentication options"
            );
        }


        // ----------------------------------------------------
        // Convert challenge
        // ----------------------------------------------------

        options.challenge =
            base64urlToBuffer(
                options.challenge
            );


        // ----------------------------------------------------
        // Convert allowed credential IDs
        // ----------------------------------------------------

        if (
            options.allowCredentials
        ) {

            options.allowCredentials =
                options.allowCredentials.map(
                    item => ({

                        ...item,

                        id:
                            base64urlToBuffer(
                                item.id
                            )

                    })
                );
        }


        // ----------------------------------------------------
        // Ask iPhone for Face ID
        // ----------------------------------------------------

        result.innerText =
            "Look at your iPhone for Face ID...";


        const authCredential =
            await navigator.credentials.get({

                publicKey:
                    options

            });


        if (!authCredential) {

            throw new Error(
                "Authentication was cancelled."
            );
        }


        // ----------------------------------------------------
        // Prepare authentication response
        // ----------------------------------------------------

        const responseData = {

            id:
                authCredential.id,

            rawId:
                bufferToBase64url(
                    authCredential.rawId
                ),

            type:
                authCredential.type,

            response: {

                clientDataJSON:
                    bufferToBase64url(
                        authCredential.response
                            .clientDataJSON
                    ),

                authenticatorData:
                    bufferToBase64url(
                        authCredential.response
                            .authenticatorData
                    ),

                signature:
                    bufferToBase64url(
                        authCredential.response
                            .signature
                    )
            }
        };


        // ----------------------------------------------------
        // Send to Acer
        // ----------------------------------------------------

        result.innerText =
            "Verifying Face ID with Acer...";


        const verifyResponse =
            await fetch(
                "/authenticate/verify",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify(
                            responseData
                        )

                }
            );


        const verification =
            await verifyResponse.json();


        if (!verifyResponse.ok) {

            throw new Error(
                verification.error ||
                "Authentication verification failed."
            );
        }


        // ----------------------------------------------------
        // SUCCESS
        // ----------------------------------------------------

        result.innerText =
            "✅ AUTHENTICATED!\\n\\n" +
            "Face ID verified successfully.\\n" +
            "Acer unlocked.";

        result.className =
            "success";


    }

    catch (error) {

        console.error(
            "Authentication error:",
            error
        );

        result.innerText =
            "❌ Authentication failed\\n\\n" +
            error.message;

        result.className =
            "error";
    }


    finally {

        button.disabled =
            false;
    }
}


// ============================================================
// START
// ============================================================

setupPage();

</script>

</body>

</html>
"""


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template_string(HTML)


# ============================================================
# STATUS
# ============================================================

@app.route("/status")
def status():

    return jsonify({

        "service":
            "FaceUnlock",

        "status":
            "running",

        "iphone_registered":
            credential is not None

    })


# ============================================================
# REGISTRATION OPTIONS
# ============================================================

@app.route("/register/options")
def register_options():

    global registration_challenge

    try:

        options = generate_registration_options(
                rp_id=RP_ID,
                rp_name=RP_NAME,

                user_id=USER_ID,
                user_name=USER_NAME,
                user_display_name=USER_DISPLAY_NAME,

                timeout=60000,
            )

        registration_challenge = options.challenge

        return options_to_json(options)


    except Exception as e:

        print("Registration options error:")
        print(type(e).__name__)
        print(e)

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# REGISTRATION VERIFY
# ============================================================

@app.route(
    "/register/verify",
    methods=["POST"]
)
def register_verify():

    global credential

    try:

        if registration_challenge is None:

            return jsonify({
                "error":
                    "No registration challenge exists."
            }), 400


        data = request.get_json()


        if not data:

            return jsonify({
                "error":
                    "No JSON data received."
            }), 400


        # ----------------------------------------------------
        # Verify WebAuthn registration
        # ----------------------------------------------------

        verification = verify_registration_response(

                credential=data,

                expected_challenge=
                    registration_challenge,

                expected_rp_id=
                    RP_ID,

                expected_origin=
                    ORIGIN,

            )


        # ----------------------------------------------------
        # IMPORTANT
        #
        # Store raw credential public key as Base64.
        # Do NOT convert it to JSON/CBOR.
        # ----------------------------------------------------

        credential = {

            "credential_id":
                bytes_to_base64url(
                    verification.credential_id
                ),

            "public_key":
                base64.b64encode(
                    verification.credential_public_key
                ).decode("utf-8"),

            "sign_count":
                verification.sign_count,

            "user":
                USER_NAME

        }


        # ----------------------------------------------------
        # Permanently save credential
        # ----------------------------------------------------

        save_credential(
            credential
        )


        print("")
        print("===================================")
        print(" iPhone WebAuthn registration OK")
        print(" Credential saved permanently")
        print("===================================")
        print("")


        return jsonify({

            "status":
                "registered"

        })


    except Exception as e:

        print("")
        print("===================================")
        print("REGISTRATION ERROR")
        print("===================================")
        print("Type:", type(e).__name__)
        print("Error:", e)
        print("===================================")
        print("")

        return jsonify({

            "error":
                str(e)

        }), 400


# ============================================================
# AUTHENTICATION OPTIONS
# ============================================================

@app.route("/authenticate/options")
def authenticate_options():

    global authentication_challenge

    try:

        if credential is None:

            return jsonify({

                "error":
                    "No iPhone is registered."

            }), 400


        # ----------------------------------------------------
        # Generate fresh challenge
        # ----------------------------------------------------

        authentication_challenge = secrets.token_bytes(32)


        # ----------------------------------------------------
        # Tell WebAuthn which credential is allowed
        # ----------------------------------------------------

        allow_credentials = [

            PublicKeyCredentialDescriptor(

                id=
                    base64url_to_bytes(
                        credential[
                            "credential_id"
                        ]
                    )

            )

        ]


        # ----------------------------------------------------
        # Generate authentication options
        # ----------------------------------------------------

        options = generate_authentication_options(

                rp_id=
                    RP_ID,

                challenge=
                    authentication_challenge,

                timeout=
                    60000,

                allow_credentials=
                    allow_credentials,

                user_verification=
                    UserVerificationRequirement.REQUIRED

            )


        return options_to_json(
            options
        )


    except Exception as e:

        print("Authentication options error:")
        print(type(e).__name__)
        print(e)

        return jsonify({

            "error":
                str(e)

        }), 500


# ============================================================
# AUTHENTICATION VERIFY
# ============================================================

@app.route(
    "/authenticate/verify",
    methods=["POST"]
)
def authenticate_verify():

    global credential

    try:

        if credential is None:

            return jsonify({

                "error":
                    "No iPhone is registered."

            }), 400


        if authentication_challenge is None:

            return jsonify({

                "error":
                    "No authentication challenge exists."

            }), 400


        data = request.get_json()


        if not data:

            return jsonify({

                "error":
                    "No JSON data received."

            }), 400


        # ----------------------------------------------------
        # Decode stored public key
        # ----------------------------------------------------

        stored_public_key = base64.b64decode(
                credential["public_key"]
            )


        # ----------------------------------------------------
        # Verify authentication
        # ----------------------------------------------------

        verification = verify_authentication_response(

                credential=data,

                expected_challenge=
                    authentication_challenge,

                expected_rp_id=
                    RP_ID,

                expected_origin=
                    ORIGIN,

                credential_public_key=
                    stored_public_key,

                credential_current_sign_count=
                    credential["sign_count"],

                require_user_verification=
                    True,

            )


        # ----------------------------------------------------
        # Update sign counter
        # ----------------------------------------------------

        credential["sign_count"] = verification.new_sign_count


        # ----------------------------------------------------
        # Save updated credential
        # ----------------------------------------------------

        save_credential(
            credential
        )


        print("")
        print("===================================")
        print(" iPhone authentication SUCCESS")
        print(" Face ID verified")
        print(" ===================================")
        print("")


        return jsonify({

            "status":
                "authenticated",

            "message":
                "Face ID authentication successful"

        })


    except Exception as e:

        print("")
        print("===================================")
        print("AUTHENTICATION ERROR")
        print("===================================")
        print("Type:", type(e).__name__)
        print("Error:", e)

        if e.__cause__ is not None:

            print(
                "CAUSE:",
                type(e.__cause__).__name__
            )

            print(
                "CAUSE ERROR:",
                e.__cause__
            )

        import traceback

        traceback.print_exc()

        print("===================================")
        print("")

        return jsonify({

            "error":
                str(e)

        }), 400


# ============================================================
# SERVER
# ============================================================

if __name__ == "__main__":

    print("")
    print("===================================")
    print(" FaceUnlock Authentication Server")
    print("===================================")

    if credential:

        print("iPhone credential: REGISTERED")

    else:

        print("iPhone credential: NOT REGISTERED")

    print("")
    print(
        "HTTPS server running on port 5443"
    )
    print(
        "https://192-168-1-69.sslip.io:5443"
    )
    print("")


    app.run(

        host="0.0.0.0",

        port=5443,

        debug=False,

        ssl_context=(

            "192-168-1-69.sslip.io.pem",

            "192-168-1-69.sslip.io-key.pem"

        )

    )