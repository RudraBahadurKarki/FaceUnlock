from pathlib import Path
import json
import platform
import socket
import time
import requests
import subprocess

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

IDENTITY_FILE = BASE_DIR / "pc_identity.json"
SECRET_FILE = BASE_DIR / "agent_secret.txt"
CERT_FILE = ROOT_DIR / "192-168-1-69.sslip.io.pem"

SERVER_URL = "https://192-168-1-69.sslip.io:5000"
HEARTBEAT_INTERVAL = 10
COMMAND_INTERVAL = 2


def load_pc_identity():
    if not IDENTITY_FILE.exists():
        raise FileNotFoundError("PC identity file not found.")

    with open(IDENTITY_FILE, "r", encoding="utf-8") as file:
        identity = json.load(file)

    pc_id = identity.get("pc_id")

    if not pc_id:
        raise ValueError("PC identity is missing pc_id.")

    return pc_id


def load_agent_secret():
    if not SECRET_FILE.exists():
        raise FileNotFoundError("Agent secret file not found.")

    with open(SECRET_FILE, "r", encoding="utf-8") as file:
        secret = file.read().strip()

    if not secret:
        raise ValueError("Agent secret is empty.")

    return secret


def get_pc_info():
    return {
        "pc_id": load_pc_identity(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
    }


def send_heartbeat(pc_info, agent_secret):
    response = requests.post(
        f"{SERVER_URL}/agent/heartbeat",
        json=pc_info,
        headers={
            "X-Agent-Secret": agent_secret
        },
        verify=str(CERT_FILE),
        timeout=5,
    )

    response.raise_for_status()

    return response.json()


def check_for_command(pc_id, agent_secret):
    response = requests.post(
        f"{SERVER_URL}/agent/command/poll",
        json={
            "pc_id": pc_id
        },
        headers={
            "X-Agent-Secret": agent_secret
        },
        verify=str(CERT_FILE),
        timeout=5,
    )

    response.raise_for_status()

    return response.json()

def handle_command(command, pc_info):
    if command == "status":
        return {
            "success": True,
            "pc_id": pc_info["pc_id"],
            "hostname": pc_info["hostname"],
            "system": pc_info["system"],
            "machine": pc_info["machine"],
            "message": "Windows Agent is running."
        }

    if command == "lock":
        try:
            result = subprocess.run(
                ["rundll32.exe", "user32.dll,LockWorkStation"],
                check=False,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "message": "Windows workstation locked."
                }

            return {
                "success": False,
                "error": "Windows lock command failed.",
                "return_code": result.returncode
            }

        except Exception as error:
            return {
                "success": False,
                "error": str(error)
            }

    return {
        "success": False,
        "error": "Command is not supported by the agent."
    }

def send_command_result(
    pc_id,
    agent_secret,
    command_id,
    result
):
    response = requests.post(
        f"{SERVER_URL}/agent/command/result",
        json={
            "pc_id": pc_id,
            "command_id": command_id,
            "result": result
        },
        headers={
            "X-Agent-Secret": agent_secret
        },
        verify=str(CERT_FILE),
        timeout=5,
    )

    response.raise_for_status()

    return response.json()

def main():
    print("============================================")
    print("          FaceUnlock Windows Agent")
    print("============================================")
    print()

    pc_info = get_pc_info()
    agent_secret = load_agent_secret()

    print(f"PC ID: {pc_info['pc_id']}")
    print(f"Hostname: {pc_info['hostname']}")
    print(f"System: {pc_info['system']}")
    print(f"Machine: {pc_info['machine']}")
    print()

    print("Connecting to FaceUnlock server...")

    last_heartbeat = 0

    while True:
        current_time = time.time()

        if current_time - last_heartbeat >= HEARTBEAT_INTERVAL:
            try:
                result = send_heartbeat(
                    pc_info,
                    agent_secret
                )

                print(
                    f"[ONLINE] "
                    f"{result.get('message', 'Heartbeat accepted.')}"
                )

                last_heartbeat = current_time

            except Exception as error:
                print(
                    f"[OFFLINE] Heartbeat failed: {error}"
                )

        try:
            command_response = check_for_command(
                pc_info["pc_id"],
                agent_secret
            )

            command = command_response.get("command")
            command_id = command_response.get("command_id")

            if command and command_id:
                print(
                    f"[COMMAND] Received: {command} "
                    f"(ID: {command_id})"
                )

                result = handle_command(
                    command,
                    pc_info
                )

                send_command_result(
                    pc_info["pc_id"],
                    agent_secret,
                    command_id,
                    result
                )

                print("[COMMAND] Result sent.")

        except Exception as error:
            print(
                f"[OFFLINE] Command connection failed: {error}"
            )

        time.sleep(COMMAND_INTERVAL)


if __name__ == "__main__":
    main()