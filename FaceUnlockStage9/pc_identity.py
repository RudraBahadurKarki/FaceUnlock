from pathlib import Path
import json
import secrets

BASE_DIR = Path(__file__).resolve().parent
IDENTITY_FILE = BASE_DIR / "pc_identity.json"


def load_or_create_identity():
    if IDENTITY_FILE.exists():
        with open(IDENTITY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    identity = {
        "pc_id": secrets.token_hex(16)
    }

    with open(IDENTITY_FILE, "w", encoding="utf-8") as file:
        json.dump(identity, file, indent=2)

    return identity


if __name__ == "__main__":
    identity = load_or_create_identity()

    print("============================================")
    print("          FaceUnlock PC Identity")
    print("============================================")
    print()
    print(f"PC ID: {identity['pc_id']}")