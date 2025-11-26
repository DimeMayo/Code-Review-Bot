import tkinter as tk
from tkinter import messagebox, scrolledtext
from database import register_user, verify_user, get_connection


# ---- DB helper: fetch all non-super users ----
def fetch_all_users():
    """
    Returns a list of dicts: [{id, username, role}, ...]
    Only students and instructors, sorted by role then username.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, username, role
            FROM users
            WHERE role IN ('student', 'instructor')
            ORDER BY role, username
            """
        )
        rows = cur.fetchall()
        return rows
    finally:
        conn.close()


# ---- DB helper: delete a user by id ----
def delete_user_by_id(user_id):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    finally:
        conn.close()


def open_super_admin_portal():
    root = tk.Tk()
    root.title("Super Admin Portal - Code Review Bot")
    root.geometry("700x500")
    root.configure(bg="#1E1E1E")

    LABEL_COLOR = "#FFFFFF"
    ENTRY_BG = "#2D2D2D"
    ENTRY_FG = "#FFFFFF"
    BUTTON_BG = "#007ACC"
    BUTTON_FG = "#FFFFFF"
    TEXT_BG = "#252526"
    TEXT_FG = "#D4D4D4"

    # ---------- LOGIN / REGISTER FRAME ----------
    login_frame = tk.Frame(root, bg="#1E1E1E")
    login_frame.pack(fill="both", expand=True)

    tk.Label(
        login_frame,
        text="Super Admin Login",
        font=("Segoe UI", 14, "bold"),
        fg="#00FFAA",
        bg="#1E1E1E"
    ).pack(pady=16)

#    hint = (
#        "Hint: Use a special username like 'superadmin' or 'superstudent'.\n"
#        "Account is stored with role='instructor', but username starting with 'super' "
#        "is treated as a super admin."
#    )
    tk.Label(
        login_frame,
        #text=hint,
        fg="#CCCCCC",
        bg="#1E1E1E",
        font=("Segoe UI", 9)
    ).pack(pady=(0, 10))

    tk.Label(login_frame, text="Username:", fg=LABEL_COLOR, bg="#1E1E1E").pack(anchor="w", padx=30)
    username_entry = tk.Entry(login_frame, width=40, bg=ENTRY_BG, fg=ENTRY_FG,
                              insertbackground="white", relief="flat")
    username_entry.pack(padx=30, pady=6)

    tk.Label(login_frame, text="Password:", fg=LABEL_COLOR, bg="#1E1E1E").pack(anchor="w", padx=30)
    password_entry = tk.Entry(login_frame, width=40, show="*", bg=ENTRY_BG, fg=ENTRY_FG,
                              insertbackground="white", relief="flat")
    password_entry.pack(padx=30, pady=6)

    status_label = tk.Label(login_frame, text="", fg="#FFD700", bg="#1E1E1E")
    status_label.pack(pady=6)

    # ---------- After login: admin view ----------
    def show_admin_view(super_username):
        login_frame.destroy()

        admin_frame = tk.Frame(root, bg="#1E1E1E")
        admin_frame.pack(fill="both", expand=True)

        tk.Label(
            admin_frame,
            text=f"Super Admin – Users Overview",
            font=("Segoe UI", 14, "bold"),
            fg="#00FFAA",
            bg="#1E1E1E"
        ).pack(pady=12)

        tk.Label(
            admin_frame,
            text="All registered students and instructors (click [X] to delete):",
            fg=LABEL_COLOR,
            bg="#1E1E1E",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=20, pady=(4, 2))

        text_box = scrolledtext.ScrolledText(
            admin_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            bg=TEXT_BG,
            fg=TEXT_FG,
            insertbackground="white",
            relief="flat"
        )
        text_box.pack(padx=20, pady=10, fill="both", expand=True)

        # line -> user mapping so we know which user is on each line
        line_to_user = {}

        def refresh_users():
            text_box.config(state=tk.NORMAL)
            text_box.delete(1.0, tk.END)
            line_to_user.clear()
            try:
                users = fetch_all_users()
                if not users:
                    text_box.insert(tk.END, "No students or instructors found.\n")
                else:
                    header = f"{'ID':<6} {'Username':<24} {'Role':<12}  [X]\n"
                    text_box.insert(tk.END, header)
                    text_box.insert(tk.END, "-" * 65 + "\n")
                    current_line = 3  # header=1, separator=2, data starts at line 3
                    for u in users:
                        line_text = f"{u['id']:<6} {u['username']:<24} {u['role']:<12}  [X]\n"
                        text_box.insert(tk.END, line_text)
                        line_to_user[current_line] = u
                        current_line += 1
            except Exception as e:
                text_box.insert(tk.END, f"Error fetching users: {e}\n")
            text_box.config(state=tk.DISABLED)

        def on_text_click(event):
            # Get the index of the click inside the text widget
            idx = text_box.index(f"@{event.x},{event.y}")
            line_str, col_str = idx.split(".")
            line = int(line_str)
            col = int(col_str)

            user = line_to_user.get(line)
            if not user:
                return  # clicked header/empty area

            # Get the text of the clicked line
            line_text = text_box.get(f"{line}.0", f"{line}.end")
            # Position of "[X]" at end of the line
            x_pos = line_text.rfind("[X]")

            # Only treat it as delete click if user clicked near the [X]
            if x_pos == -1:
                return
            if col < x_pos:
                return  # clicked earlier in the line, ignore

            # Confirm deletion
            if not messagebox.askyesno(
                "Confirm Delete",
                f"Delete user '{user['username']}' with role '{user['role']}'?"
            ):
                return

            try:
                delete_user_by_id(user["id"])
                messagebox.showinfo("Deleted", f"User '{user['username']}' deleted.")
                refresh_users()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete user: {e}")

        text_box.bind("<Button-1>", on_text_click)

        refresh_users()

        # Buttons row (Refresh + Logout)
        btn_frame = tk.Frame(admin_frame, bg="#1E1E1E")
        btn_frame.pack(pady=8)

        refresh_btn = tk.Button(
            btn_frame,
            text="Refresh",
            command=refresh_users,
            bg="#4CAF50",
            fg="white",
            padx=10,
            pady=5,
            relief="flat"
        )
        refresh_btn.grid(row=0, column=0, padx=8)

        def on_logout():
            root.destroy()

        logout_btn = tk.Button(
            btn_frame,
            text="Logout / Close",
            command=on_logout,
            bg="#E53935",
            fg="white",
            padx=10,
            pady=5,
            relief="flat"
        )
        logout_btn.grid(row=0, column=1, padx=8)

    # ---------- Login & Register handlers ----------
    def on_login():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password.")
            return

        user = verify_user(username, password)
        if not user:
            messagebox.showerror("Error", "Invalid username or password.")
            return

        # SUPER ADMIN RULE:
        # Any valid user whose username starts with 'super' is treated as super admin.
        if not user["username"].lower().startswith("super"):
            messagebox.showerror(
                "Unauthorized",
                f"User '{user['username']}' is not a super admin (username must start with 'super')."
            )
            return

        messagebox.showinfo("Welcome", f"Logged in as super admin: {user['username']}")
        show_admin_view(user["username"])

    def on_register_superadmin():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Enter username and password to register.")
            return

        # SUPER ADMIN REGISTRATION:
        # We store role='instructor' so the SQL constraint is happy,
        # but username starting with 'super' marks it as super admin in code logic.
        if not username.lower().startswith("super"):
            if not messagebox.askyesno(
                "Confirm",
                "Username does not start with 'super'.\n"
                "It is recommended to start super admin usernames with 'super'.\n\n"
                "Continue anyway?"
            ):
                return

        try:
            ok = register_user(username, password, "instructor")
        except Exception as e:
            print("register_user error:", e)
            ok = False

        if ok:
            status_label.config(
                text="Super admin registered (stored as role='instructor'). You can now login.",
                fg="#7CFC00"
            )
            messagebox.showinfo(
                "Registered",
                f"Super admin account created for '{username}'."
            )
        else:
            messagebox.showerror(
                "Error",
                "Registration failed (username may already exist)."
            )

    btn_row = tk.Frame(login_frame, bg="#1E1E1E")
    btn_row.pack(pady=12)

    login_btn = tk.Button(
        btn_row,
        text="Login",
        width=12,
        command=on_login,
        bg="#4CAF50",
        fg=BUTTON_FG,
        relief="flat"
    )
    login_btn.grid(row=0, column=0, padx=8)

 #   register_btn = tk.Button(
 #       btn_row,
 #       text="Register Superadmin",
 #       width=18,
 #       command=on_register_superadmin,
 #       bg=BUTTON_BG,
 #       fg=BUTTON_FG,
 #       relief="flat"
 #   )
 #   register_btn.grid(row=0, column=1, padx=8)

    root.mainloop()


if __name__ == "__main__":
    open_super_admin_portal()