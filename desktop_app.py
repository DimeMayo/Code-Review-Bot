import os
from dotenv import load_dotenv
from openai import OpenAI
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re
import keyword


load_dotenv()


client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
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

root.mainloop()


