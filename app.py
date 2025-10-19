import os
import time
import jwt
import requests
from github import Github, Auth
from dotenv import load_dotenv

load_dotenv()

APP_ID = os.getenv("APP_ID")
INSTALLATION_ID = int(os.getenv("INSTALLATION_ID"))
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")
REPO_FULL_NAME = os.getenv("REPO_FULL_NAME")

# Load private key
with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

# Authenticate as the app installation
auth = Auth.AppAuth(app_id=APP_ID, private_key=PRIVATE_KEY)
github_client = Github(auth=auth)
jwt_token = auth.create_jwt()  # Short-lived JWT for the App itself

url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
headers = {
    "Authorization": f"Bearer {jwt_token}",
    "Accept": "application/vnd.github+json",
}

response = requests.post(url, headers=headers)
response.raise_for_status()

access_token = response.json()["token"]

installation_auth = Auth.Token(access_token)
installation_client = Github(auth=installation_auth)

def analyze_and_comment(code_text):
    """Insert comments directly into Python source code."""
    lines = code_text.splitlines()
    new_lines = []
    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip adding if this line is already a comment from the bot
        if stripped.startswith("# ⚠️") or stripped.startswith("# 📝") or stripped.startswith("# ✅"):
            new_lines.append(line)
            continue

        # Add warnings only if not already present in nearby lines
        if "print(" in stripped:
            if not any("Avoid using print()" in l for l in new_lines[-2:]):  # Check last few lines
                new_lines.append("# ⚠️ Avoid using print() in production code.")
        elif "TODO" in stripped:
            if not any("Remember to remove TODO" in l for l in new_lines[-2:]):
                new_lines.append("# 📝 Remember to remove TODO comments before merging.")
        elif "eval(" in stripped:
            if not any("Avoid using eval()" in l for l in new_lines[-2:]):
                new_lines.append("# ⚠️ Avoid using eval() for security reasons.")
        else:
            # No match, keep line as-is
            pass
        new_lines.append(line)
    return "\n".join(new_lines)

def find_main_python_file(repo):
    """Find the first Python (.py) file in the repo root."""
    print("🔍 Searching for Python files in the root directory...")
    contents = repo.get_contents("")
    for file in contents:
        if file.name.endswith(".py"):
            print(f"✅ Found Python file: {file.path}")
            return file
    print("❌ No Python files found in the repository root.")
    return None

def review_and_update_file():
    """Fetch, analyze, comment, and commit the updated file."""
    repo = installation_client.get_repo(REPO_FULL_NAME)
    file = find_main_python_file(repo)
    if not file:
        print("⚠️ Could not find a Python file to analyze.")
        return

    code = file.decoded_content.decode()
    commented_code = analyze_and_comment(code)

    if code == commented_code:
        print("✅ No changes needed — code looks clean!")
        return

    # Commit the commented file back to the repo
    commit_message = "🤖 Code review comments added by GitHub bot"
    repo.update_file(
        path=file.path,
        message=commit_message,
        content=commented_code,
        sha=file.sha,
        branch="main",
    )

    print(f"✅ Comments added and committed to {file.path}!")

if __name__ == "__main__":
    print("🚀 Starting GitHub Auto Comment Bot")
    review_and_update_file()
    print("✅ Done!")