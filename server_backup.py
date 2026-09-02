from flask import Flask, jsonify, render_template_string
import secrets
import time

app = Flask(__name__)

current_challenge = None
challenge_created_at = None

HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>FaceUnlock Test</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px 20px;
        }

        button {
            padding: 15px 25px;
            font-size: 18px;
            border-radius: 10px;
            border: none;
            background: #007aff;
            color: white;
        }

        #result {
            margin-top: 25px;
            word-break: break-word;
        }
    </style>
</head>

<body>

    <h1>🔐 FaceUnlock</h1>

    <p>iPhone → Acer connection test</p>

    <button onclick="testConnection()">
        Test Authentication
    </button>

    <div id="result"></div>

    <script>
        async function testConnection() {
            const result = document.getElementById("result");

            result.innerText = "Contacting Acer...";

            try {
                const response = await fetch("/challenge");
                const data = await response.json();

                result.innerText =
                    "Acer connected!\\n\\nChallenge:\\n" +
                    data.challenge;

            } catch (error) {
                result.innerText =
                    "Connection failed: " + error;
            }
        }
    </script>

</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/challenge")
def challenge():
    global current_challenge
    global challenge_created_at

    current_challenge = secrets.token_urlsafe(32)
    challenge_created_at = time.time()

    return jsonify({
        "challenge": current_challenge,
        "expires_in": 60
    })


@app.route("/status")
def status():
    return jsonify({
        "service": "FaceUnlock",
        "status": "running"
    })


if __name__ == "__main__":
    print("===================================")
    print(" FaceUnlock Authentication Server")
    print("===================================")
    print("HTTPS server running on port 5443")
    print("")

    app.run(
        host="0.0.0.0",
        port=5443,
        debug=False,
        ssl_context=(
            "192.168.1.69+2.pem",
            "192.168.1.69+2-key.pem"
        )
    )