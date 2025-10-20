import os
import time
import jwt
import requests
from github import Github, Auth
from dotenv import load_dotenv
from openai import OpenAI

if os.getenv("GITHUB_ACTIONS") is None:
    # Running locally
    load_dotenv()
    print("🧩 Loaded local .env file")
else:
    print("🚀 Running inside GitHub Actions, using repository secrets")

APP_ID = os.getenv("APP_ID")
INSTALLATION_ID = int(os.getenv("INSTALLATION_ID"))
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
REPO_FULL_NAME = os.getenv("REPO_FULL_NAME")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if INSTALLATION_ID:
    INSTALLATION_ID = int(INSTALLATION_ID)
else:
    raise ValueError("❌ INSTALLATION_ID environment variable not found!")

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

client = OpenAI(api_key=OPENAI_API_KEY)
    
def analyze_and_comment(code_text, requirements_text=None):
    """
    Analyze the code for both quality and assignment requirement completion.
    Adds inline "# AI Review:" comments above relevant lines.
    """

    # Clean up existing comments
    lines = [l for l in code_text.splitlines() if not l.strip().startswith("# AI Review:")]
    joined_code = "\n".join(lines)

    if requirements_text:
        prompt = f"""
You are an expert teaching assistant reviewing a student's Python code for an assignment.
Here are the assignment requirements:

{requirements_text}

Review the following code. For each requirement, check if it is met or not.
If something is missing, implemented incorrectly, or can cause a bug, insert a comment above
the relevant code line, starting with "# AI Review:" explaining the issue and
how to fix it. If everything looks fine for a requirement, you don't need to comment.
Include any missing requirements as comments at the start of the code and analyze their 
progress as a percentage.

Be specific, concise, and avoid redundant comments.
Do not add "```python" at the start of the code and "```" at the end of the code.

Code:
{joined_code}
"""
    else:
        prompt = f"""
You are an expert Python reviewer.
Review the following code for possible bugs or improvements. Insert inline comments
starting with "# AI Review:" ABOVE the relevant lines. Avoid duplicates and noise.

Code:
{joined_code}
"""

    # Call OpenAI API
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are an expert Python code reviewer."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
    )

    reviewed_code = response.choices[0].message.content.strip()

    # Remove duplicate comments
    reviewed_lines = []
    last_comment = None
    for line in reviewed_code.splitlines():
        stripped = line.strip()
        if stripped.startswith("# AI Review:"):
            if stripped == last_comment:
                continue
            last_comment = stripped
        else:
            last_comment = None
        reviewed_lines.append(line)

    return "\n".join(reviewed_lines)


def find_requirement_file(repo):
    """Find the first Python (.py) file in the repo root."""
    print("🔍 Searching for Requirement text files in the root directory...")
    contents = repo.get_contents("")
    for file in contents:
        if file.name.endswith(".txt"):
            print(f"✅ Found Requirement file: {file.path}")
            return file
    print("❌ No text files found in the repository root.")
    return None

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
    reqfile = find_requirement_file(repo)
    reqtext = reqfile.decoded_content.decode() if reqfile else None
    if not reqfile:
        print("⚠️ Could not find a requirement text file to analyze.")
        return
    file = find_main_python_file(repo)
    if not file:
        print("⚠️ Could not find a Python file to analyze.")
        return

    code = file.decoded_content.decode()
    commented_code = analyze_and_comment(code, requirements_text=reqtext)

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