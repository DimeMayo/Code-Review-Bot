import os
from dotenv import load_dotenv
from openai import OpenAI
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re
import keyword
from github import Github, Auth
import jwt, time, requests
from database import register_user, verify_user



load_dotenv()

APP_ID = os.getenv("APP_ID")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")

with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

auth = Auth.AppAuth(app_id=APP_ID, private_key=PRIVATE_KEY)
github_client = Github(auth=auth)


client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
def analyze_and_comment(code_text, requirements_text=None):
    """
    Analyze the code for both quality and assignment requirement completion.
    Adds inline "# AI Review:" comments above relevant lines.
    """

    
    lines = [l for l in code_text.splitlines() if not l.strip().startswith("# AI Review:")]
    joined_code = "\n".join(lines)

    if requirements_text:
        prompt = f"""
You are an expert teaching assistant reviewing a student's Python code for an assignment.
Here are the assignment requirements:

{requirements_text}

Review the following code. For each requirement, check if it is met or not.
If something is missing, implemented incorrectly, or can cause a bug, insert only a comment above
the relevant code line, starting with "# AI Review:" explaining the issue and
how to fix it. If everything looks fine for a requirement, you don't need to comment. 
Do not fix the code, add any code, or erase any code.
Include any missing requirements as comments at the top of the code and analyze their progress as a percentage.

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

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are an expert Python code reviewer."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
    )

    reviewed_code = response.choices[0].message.content.strip()

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

def colorize_textbox(textbox, content):
    textbox.config(state=tk.NORMAL)
    textbox.delete(1.0, tk.END)
    textbox.insert(tk.END, content)

    for tag in textbox.tag_names():
        textbox.tag_delete(tag)

    textbox.tag_config("ai_comment", foreground="#019208")  
    textbox.tag_config("keyword", foreground="#569CD6")     
    textbox.tag_config("string", foreground="#CE9178")      
    textbox.tag_config("number", foreground="#B5CEA8")
    textbox.tag_raise("ai_comment")      

    def apply_tag(pattern, tag):
        for match in re.finditer(pattern, content, re.MULTILINE):
            start_idx = f"1.0 + {match.start()} chars"
            end_idx = f"1.0 + {match.end()} chars"
            textbox.tag_add(tag, start_idx, end_idx)

    apply_tag(r"#.*", "ai_comment")
    apply_tag(r"(\"[^\"]*\"|'[^']*')", "string")
    apply_tag(r"\b\d+(\.\d+)?\b", "number")

    for kw in keyword.kwlist:
        apply_tag(rf"\b{kw}\b", "keyword")

    textbox.config(state=tk.DISABLED)

def select_code_file():
    file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
    code_entry.delete(0, tk.END)
    code_entry.insert(0, file_path)

def select_requirements_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    req_entry.delete(0, tk.END)
    req_entry.insert(0, file_path)

def run_review():
    code_path = code_entry.get()
    req_path = req_entry.get()

    if not os.path.exists(code_path):
        messagebox.showerror("Error", "Please select a valid Python file.")
        return

    with open(code_path, "r", encoding="utf-8") as f:
        code_text = f.read()

    requirements_text = None
    if req_path and os.path.exists(req_path):
        with open(req_path, "r", encoding="utf-8") as f:
            requirements_text = f.read()

    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "⏳ Analyzing, please wait...\n")
    result_text.config(state=tk.DISABLED)
    root.update()

    try:
        reviewed_code = analyze_and_comment(code_text, requirements_text)
        colorize_textbox(result_text, reviewed_code)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def save_output():
    reviewed = result_text.get(1.0, tk.END).strip()
    if not reviewed:
        messagebox.showinfo("Info", "No output to save.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".py")
    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(reviewed)
        messagebox.showinfo("Saved", f"Reviewed code saved to {file_path}")


def start_student_app():
    menu_window.destroy()
    open_student_app()

def open_student_app():
    global root, code_entry, req_entry, result_text

    root = tk.Tk()
    root.title("🤖 Code Review Bot")
    root.geometry("900x650")
    root.configure(bg="#1E1E1E")


    LABEL_COLOR = "#FFFFFF"
    ENTRY_BG = "#2D2D2D"
    ENTRY_FG = "#FFFFFF"
    BUTTON_BG = "#007ACC"
    BUTTON_FG = "#FFFFFF"
    TEXT_BG = "#252526"
    TEXT_FG = "#D4D4D4"

    def make_label(text):
        return tk.Label(root, text=text, bg="#1E1E1E", fg=LABEL_COLOR, font=("Segoe UI", 10, "bold"))

    def make_button(text, command, color=BUTTON_BG):
        return tk.Button(root, text=text, command=command, bg=color, fg=BUTTON_FG, activebackground="#0E639C", activeforeground="#FFFFFF", relief="flat", padx=8, pady=4)

    make_label("Python Code File:").pack(anchor="w", padx=10, pady=(10, 0))
    code_entry = tk.Entry(root, width=80, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    code_entry.pack(padx=10, pady=2)
    make_button("Browse", select_code_file).pack(pady=5)

    make_label("Requirements Text File (optional):").pack(anchor="w", padx=10, pady=(10, 0))
    req_entry = tk.Entry(root, width=80, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    req_entry.pack(padx=10, pady=2)
    make_button("Browse", select_requirements_file).pack(pady=5)

    make_button("Run Code Review", run_review, color="#4CAF50").pack(pady=10)
    make_button("Save Reviewed Code", save_output, color="#2196F3").pack(pady=5)

    make_label("Output:").pack(anchor="w", padx=10, pady=(10, 0))
    result_text = scrolledtext.ScrolledText(
        root, wrap=tk.WORD, width=95, height=22,
        bg=TEXT_BG, fg=TEXT_FG, insertbackground="white", relief="flat"
    )
    result_text.pack(padx=10, pady=10, expand=True, fill="both")

def start_instructor_app():
    menu_window.destroy()
    open_instructor_app()


def open_instructor_app():
    global instructor_root, code_entry, req_entry, result_text

    instructor_root = tk.Tk()
    instructor_root.title("👩‍🏫 Instructor Code Review")
    instructor_root.geometry("900x800")
    instructor_root.configure(bg="#1E1E1E")

    LABEL_COLOR = "#FFFFFF"
    ENTRY_BG = "#2D2D2D"
    ENTRY_FG = "#FFFFFF"
    BUTTON_BG = "#007ACC"
    BUTTON_FG = "#FFFFFF"
    TEXT_BG = "#252526"
    TEXT_FG = "#D4D4D4"

    def make_label(text):
        return tk.Label(instructor_root, text=text, bg="#1E1E1E", fg=LABEL_COLOR, font=("Segoe UI", 10, "bold"))

    def make_button(text, command, color=BUTTON_BG):
        return tk.Button(instructor_root, text=text, command=command, bg=color, fg=BUTTON_FG, activebackground="#0E639C", activeforeground="#FFFFFF", relief="flat", padx=8, pady=4)

    make_label("Requirements Text File (optional):").pack(anchor="w", padx=10, pady=(10, 0))
    req_entry = tk.Entry(instructor_root, width=70, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    req_entry.pack(padx=10, pady=2)
    make_button("Browse", select_requirements_file).pack(pady=5)

    make_label("Organization Name:").pack(anchor="w", padx=10, pady=(10, 0))
    org_entry = tk.Entry(instructor_root, width=50, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    org_entry.pack(padx=10, pady=5)

    repo_listbox = tk.Listbox(instructor_root, selectmode=tk.MULTIPLE, width=80, height=15, bg=TEXT_BG, fg=TEXT_FG)
    repo_listbox.pack(padx=10, pady=10, fill="both", expand=True)

    log_box = scrolledtext.ScrolledText(
        instructor_root, wrap=tk.WORD, width=95, height=15,
        bg=TEXT_BG, fg=TEXT_FG, insertbackground="white", relief="flat"
    )
    log_box.pack(padx=10, pady=10, expand=True, fill="both")

    def log(message):
        log_box.config(state=tk.NORMAL)
        log_box.insert(tk.END, f"{message}\n")
        log_box.see(tk.END)
        log_box.config(state=tk.DISABLED)
        instructor_root.update()

    def run_instructor_review():
        org_name = org_entry.get().strip()
        if not org_name:
            messagebox.showerror("Error", "Please enter an organization name.")
            return

        requirements_text = None
        req_path = req_entry.get().strip()
        if req_path and os.path.exists(req_path):
            with open(req_path, "r", encoding="utf-8") as f:
                requirements_text = f.read()

        try:
            log(f"Authenticating as GitHub App (App ID: {APP_ID})...")

            # Create JWT for GitHub App authentication
            payload = {
                "iat": int(time.time()) - 60,
                "exp": int(time.time()) + (10 * 60),
                "iss": APP_ID
            }
            app_jwt = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

            headers = {"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"}
            log("Fetching app installations...")

            # Fetch installations for this GitHub App
            response = requests.get("https://api.github.com/app/installations", headers=headers)
            response.raise_for_status()
            installations = response.json()

            installation_id = None
            for inst in installations:
                if inst["account"]["login"].lower() == org_name.lower():
                    installation_id = inst["id"]
                    break

            if not installation_id:
                messagebox.showerror("Error", f"The app is not installed on the organization '{org_name}'.")
                return

            log(f"Found installation for '{org_name}' (ID: {installation_id})")

            # Create installation access token
            token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
            token_response = requests.post(token_url, headers=headers)
            token_response.raise_for_status()
            access_token = token_response.json()["token"]

            # Use token to authenticate with PyGithub
            installation_client = Github(auth=Auth.Token(access_token))
            org = installation_client.get_organization(org_name)
            repos = org.get_repos()

            log(f"Connected to organization '{org_name}' — found {repos.totalCount} repositories.")
            log("Starting AI code review across all repositories...\n")

            for repo in repos:
                log(f"\nReviewing repository: {repo.name}")
                try:
                    process_repository(repo, requirements_text, log)
                except Exception as e:
                    log(f"Error in {repo.name}: {e}")

            log("\nCode review completed for all repositories.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to process organization: {e}")

    def process_repository(repo, requirements_text, log):
        # Create a safe branch for reviewed code
        base_branch = repo.default_branch
        branch_name = "ai-code-review"

        try:
            base_ref = repo.get_git_ref(f"heads/{base_branch}")
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_ref.object.sha)
            log(f"Created branch '{branch_name}' from '{base_branch}'")
        except Exception:
            log(f"ℹBranch '{branch_name}' already exists. Continuing...")

        def walk_directory(path=""):
            contents = repo.get_contents(path)
            for content_file in contents:
                if content_file.type == "dir":
                    walk_directory(content_file.path)
                elif content_file.name.endswith(".py"):
                    log(f"Analyzing {content_file.path}")
                    code = content_file.decoded_content.decode("utf-8")
                    reviewed_code = analyze_and_comment(code, requirements_text)

                    if reviewed_code.strip() != code.strip():
                        try:
                            latest_file = repo.get_contents(content_file.path, ref=branch_name)
                            current_sha = latest_file.sha

                            repo.update_file(
                                path=content_file.path,
                                message=f"🤖 AI Code Review: Updated {content_file.name}",
                                content=reviewed_code,
                                sha=current_sha,
                                branch=branch_name
                            )
                            log(f"Updated {content_file.path}")
                        except Exception as e:
                            if "409" in str(e):
                                log(f"Skipped {content_file.path}: conflict (file changed upstream)")
                            else:
                                log(f"Error updating {content_file.path}: {e}")
                    else:
                        log(f"No changes needed for {content_file.path}")

        walk_directory()

    make_button("Run Organization Review", run_instructor_review, color="#4CAF50").pack(pady=10)


# --- AUTH UI: open_auth_window(role) and menu wiring ----------------

def open_auth_window(role):
    """
    role: 'student' or 'instructor'
    This opens a window where the user can login OR register.
    On successful login/register it will open the appropriate app window.
    """
    # Close the menu window (we only have one menu_window in global scope)
    try:
        menu_window.destroy()
    except Exception:
        pass

    auth_window = tk.Tk()
    auth_window.title(f"{role.title()} Login / Register - Code Review Bot")
    auth_window.geometry("420x420")
    auth_window.configure(bg="#1E1E1E")

    LABEL_COLOR = "#FFFFFF"
    ENTRY_BG = "#2D2D2D"
    ENTRY_FG = "#FFFFFF"
    BUTTON_BG = "#007ACC"
    BUTTON_FG = "#FFFFFF"

    tk.Label(auth_window, text=f"{role.title()} — Login or Register", font=("Segoe UI", 14, "bold"),
             fg="#00FFAA", bg="#1E1E1E").pack(pady=14)

    # Username
    tk.Label(auth_window, text="Username:", fg=LABEL_COLOR, bg="#1E1E1E").pack(anchor="w", padx=20)
    username_entry = tk.Entry(auth_window, width=40, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    username_entry.pack(padx=20, pady=6)

    # Password
    tk.Label(auth_window, text="Password:", fg=LABEL_COLOR, bg="#1E1E1E").pack(anchor="w", padx=20)
    password_entry = tk.Entry(auth_window, width=40, show="*", bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    password_entry.pack(padx=20, pady=6)

    # Optional: Email (if your register_user doesn't accept email, this will be ignored)
    # Comment out if you don't want email
    tk.Label(auth_window, text="Email (optional):", fg=LABEL_COLOR, bg="#1E1E1E").pack(anchor="w", padx=20)
    email_entry = tk.Entry(auth_window, width=40, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    email_entry.pack(padx=20, pady=6)

    status_label = tk.Label(auth_window, text="", fg="#FFD700", bg="#1E1E1E")
    status_label.pack(pady=6)

    def on_login():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password.")
            return

        user = verify_user(username, password)
        if user:
            # optional sanity check: ensure role matches
            if "role" in user and user["role"] != role:
                messagebox.showerror("Unauthorized", f"Account is a '{user['role']}' not a '{role}'.")
                return

            messagebox.showinfo("Success", f"Welcome back, {username} ({role})!")
            auth_window.destroy()
            if role == "student":
                open_student_app()
            else:
                open_instructor_app()
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def on_register():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        email = email_entry.get().strip()  # kept if you later add email to register_user
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password to register.")
            return

        # call your register function (signature: register_user(username, password, role))
        ok = False
        try:
            ok = register_user(username, password, role)
        except Exception as e:
            print("register_user error:", e)
            ok = False

        if ok:
            messagebox.showinfo("Registered", f"Account created for {username} as {role}. You can now login.")
            status_label.config(text="Registration successful — please login.", fg="#7CFC00")
        else:
            messagebox.showerror("Error", "Registration failed (username may already exist).")

    def on_back():
        # Destroy auth window and go back to the main menu
        auth_window.destroy()
        show_main_menu()

    btn_frame = tk.Frame(auth_window, bg="#1E1E1E")
    btn_frame.pack(pady=10)

    login_btn = tk.Button(btn_frame, text="Login", width=12, command=on_login, bg="#4CAF50", fg="white", relief="flat")
    login_btn.grid(row=0, column=0, padx=8, pady=6)

    register_btn = tk.Button(btn_frame, text="Register", width=12, command=on_register, bg="#007ACC", fg="white", relief="flat")
    register_btn.grid(row=0, column=1, padx=8, pady=6)

    back_btn = tk.Button(auth_window, text="Back", command=on_back, bg="#E53935", fg="white", width=12, relief="flat")
    back_btn.pack(pady=6)

    auth_window.mainloop()


def show_main_menu():
    """
    Recreate the main menu window (used when the user hits Back from the auth page).
    This mirrors the original main menu layout.
    """
    global menu_window
    menu_window = tk.Tk()
    menu_window.title("Code Review Bot 🤖")
    menu_window.geometry("900x650")
    menu_window.configure(bg="#1E1E1E")

    tk.Label(
        menu_window,
        text="Code Review Bot!",
        font=("Arial", 20, "bold"),
        fg="#00FFAA",
        bg="#1E1E1E"
    ).pack(pady=60)

    tk.Label(
        menu_window,
        text="Are you a student or instructor?",
        font=("Arial", 12),
        fg="white",
        bg="#1E1E1E"
    ).pack(pady=10)

    tk.Button(
        menu_window,
        text="Student",
        font=("Arial", 14),
        bg="#4CAF50",
        fg="white",
        padx=20,
        pady=10,
        command=lambda: open_auth_window("student")
    ).pack(pady=20)

    tk.Button(
        menu_window,
        text="Instructor",
        font=("Arial", 14),
        bg="#4CAF50",
        fg="white",
        padx=20,
        pady=10,
        command=lambda: open_auth_window("instructor")
    ).pack(pady=20)

    tk.Button(
        menu_window,
        text="Exit",
        font=("Arial", 12),
        bg="#E53935",
        fg="white",
        padx=15,
        pady=8,
        command=menu_window.destroy
    ).pack(pady=10)

    menu_window.mainloop()


# Replace the original menu_window creation with show_main_menu() call:
# (remove or comment out the old `menu_window = tk.Tk()` ... block and call this instead)
if __name__ == "__main__":
    show_main_menu()



