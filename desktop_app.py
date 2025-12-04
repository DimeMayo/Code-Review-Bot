
import requests
import os
from dotenv import load_dotenv
from openai import OpenAI
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re
import keyword
from github import Github, Auth
import jwt, time
from database import register_user, verify_user
from super_admin_app import open_super_admin_portal

BACKEND_URL = "https://updated-backend-ii69.onrender.com/analyze"

def analyze_and_comment(code_text, requirements_text=None):

    payload = {
        "code": code_text,
        "requirements": requirements_text
    }

    r = requests.post(BACKEND_URL, json=payload)

    if r.status_code != 200:
        raise Exception("Backend error: " + r.text)

    return r.json()["review"]

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
    root.title("🤖 Code Review Bot - Student")
    root.minsize(900, 650)
    root.geometry("1100x750")  
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
        return tk.Button(
            root,
            text=text,
            command=command,
            bg=color,
            fg=BUTTON_FG,
            activebackground="#0E639C",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=8,
            pady=4
        )

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

    # 🔴 Logout button
    def on_logout():
        root.destroy()
        show_main_menu()

    logout_btn = tk.Button(
        root,
        text="Logout",
        command=on_logout,
        bg="#E53935",
        fg="white",
        padx=10,
        pady=5,
        relief="flat"
    )
    logout_btn.pack(pady=8)




def start_instructor_app():
    menu_window.destroy()
    open_instructor_app()


def open_instructor_app():
    global instructor_root, code_entry, req_entry, result_text

    instructor_root = tk.Tk()
    instructor_root.title("👩‍🏫 Instructor Code Review")
    instructor_root.geometry("1200x850")   # more room for repo list + logs + buttons
    instructor_root.minsize(1000, 750)
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
        return tk.Button(
            instructor_root,
            text=text,
            command=command,
            bg=color,
            fg=BUTTON_FG,
            activebackground="#0E639C",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=8,
            pady=4
        )

    make_label("Requirements Text File (optional):").pack(anchor="w", padx=10, pady=(10, 0))
    req_entry = tk.Entry(instructor_root, width=70, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    req_entry.pack(padx=10, pady=2)
    make_button("Browse", select_requirements_file).pack(pady=5)

    make_label("Organization Name:").pack(anchor="w", padx=10, pady=(10, 0))
    org_entry = tk.Entry(instructor_root, width=50, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    org_entry.pack(padx=10, pady=5)

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
        req_text = None

        # read requirements file from desktop
        path = req_entry.get()
        if path and os.path.exists(path):
            with open(path, "r") as f:
                req_text = f.read()

        data = {
            "organization": org_name,
            "requirements": req_text
        }
        log(f"Connected to organization '{org_name}'")
        log("Starting AI code review across all repositories...\n")
        requests.post("https://updated-backend-ii69.onrender.com/instructor_review", json=data)

        log("\nCode review completed for all repositories.")

    make_button("Run Organization Review", run_instructor_review, color="#4CAF50").pack(pady=10)

    # 🔴 Logout button
    def on_logout():
        instructor_root.destroy()
        show_main_menu()

    logout_btn = tk.Button(
        instructor_root,
        text="Logout",
        command=on_logout,
        bg="#E53935",
        fg="white",
        padx=10,
        pady=5,
        relief="flat"
    )
    logout_btn.pack(pady=8)

    instructor_root.mainloop()
    

# --- AUTH UI: open_auth_window(role) and menu wiring ----------------
def open_auth_window(role):
    """
    role: 'student' or 'instructor'
    This opens a window where the user can login OR register.
    On successful login/register it will open the appropriate app window.
    """
    global menu_window

    # Close the menu window if it exists
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

    tk.Label(
        auth_window,
        text=f"{role.title()} — Login or Register",
        font=("Segoe UI", 14, "bold"),
        fg="#00FFAA",
        bg="#1E1E1E"
    ).pack(pady=14)

    # Username
    tk.Label(auth_window, text="Username:", fg=LABEL_COLOR, bg="#1E1E1E").pack(anchor="w", padx=20)
    username_entry = tk.Entry(auth_window, width=40, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    username_entry.pack(padx=20, pady=6)

    # Password
    tk.Label(auth_window, text="Password:", fg=LABEL_COLOR, bg="#1E1E1E").pack(anchor="w", padx=20)
    password_entry = tk.Entry(auth_window, width=40, show="*", bg=ENTRY_BG, fg=ENTRY_FG, insertbackground="white", relief="flat")
    password_entry.pack(padx=20, pady=6)

    # Email (optional)
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

        try:
            response = requests.post(
                f"https://updated-backend-ii69.onrender.com/login",
                json={"username": username, "password": password},
                timeout=6
            )
            data = response.json()
        except Exception as e:
            messagebox.showerror("Network Error", f"Could not reach backend:\n{e}")
            return

        if not data.get("success"):
            messagebox.showerror("Login Failed", data.get("message", "Unknown error"))
            return

        # Ensure correct user role
        user = data["user"]
        if user:
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
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password to register.")
            return

        try:
            response = requests.post(
                f"https://updated-backend-ii69.onrender.com/register",
                json={"username": username, "password": password, "role": role},
                timeout=6
            )
            data = response.json()
        except Exception as e:
            messagebox.showerror("Network Error", f"Cannot reach backend:\n{e}")
            return

        if data.get("success"):
            messagebox.showinfo("Registered", "Account created. You may now log in.")
            status_label.config(text="Registration successful — please login.",
                                fg="#7CFC00")
        else:
            messagebox.showerror("Error", "Registration failed (username may already exist).")

    def on_back():
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
    Main entry window. Safe to call after other windows are destroyed.
    Creates a fresh Tk root each time.
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

    # Optional: Super Admin button if you are using super_admin_app.py
    try:
        from super_admin_app import open_super_admin_portal

        tk.Button(
            menu_window,
            text="Super Admin",
            font=("Arial", 14),
            bg="#9C27B0",
            fg="white",
            padx=20,
            pady=10,
            command=open_super_admin_portal
        ).pack(pady=20)
    except ImportError:
        # If you don't have super_admin_app.py or don't want this, it's fine
        pass

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



