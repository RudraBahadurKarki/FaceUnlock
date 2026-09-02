from flask import Flask
from pathlib import Path

app = Flask(__name__)

# Certificates are stored in the parent FaceUnlock directory
BASE_DIR = Path(__file__).resolve().parent.parent

CERT_FILE = BASE_DIR / "192-168-1-69.sslip.io.pem"
KEY_FILE = BASE_DIR / "192-168-1-69.sslip.io-key.pem"


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>FaceUnlock Stage 9</title>
    </head>
    <body>
        <h1>FaceUnlock Stage 9</h1>
        <p>HTTPS server is working.</p>
    </body>
    </html>
    """


if __name__ == "__main__":

    print("============================================")
    print("       FaceUnlock Stage 9 Server")
    print("============================================")
    print()

    print("[1] Checking certificate files...")

    print(f"Certificate: {CERT_FILE}")
    print(f"Private key: {KEY_FILE}")

    if not CERT_FILE.exists():
        print("[ERROR] Certificate file not found.")
        exit(1)

    if not KEY_FILE.exists():
        print("[ERROR] Private key file not found.")
        exit(1)

    print("[OK] Certificate found.")
    print("[OK] Private key found.")
    print()

    print("[2] Starting HTTPS server...")
    print("PC: https://192-168-1-69.sslip.io:5000")
    print()

    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=(str(CERT_FILE), str(KEY_FILE))
    )