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

def analyze_diff(diff_text):
    """Simple code review rule example."""
    if "print(" in diff_text:
        return "⚠️ Avoid using print() in production code."
    elif "TODO" in diff_text:
        return "📝 Remember to remove TODO comments before merging."
    else:
        return "✅ Looks good!"

def review_open_prs():
    repo = installation_client.get_repo(REPO_FULL_NAME)
    open_prs = repo.get_pulls(state="open")
    print(f"Found {open_prs.totalCount} open pull request(s).")

    for pr in open_prs:
        print(f"Reviewing PR #{pr.number}: {pr.title}")
        comments = []
        for file in pr.get_files():
            if file.patch:
                analysis = analyze_diff(file.patch)
                comments.append(f"**{file.filename}** → {analysis}")
        
        if comments:
            comment_body = "🤖 **Automated Code Review:**\n\n" + "\n".join(comments)
            pr.create_issue_comment(comment_body)
            print(f"Commented on PR #{pr.number}")
        else:
            print(f"No changes to analyze for PR #{pr.number}")

if __name__ == "__main__":
    print("🚀 Starting GitHub Code Review Bot (no webhooks)")
    review_open_prs()
    print("✅ Review complete!")