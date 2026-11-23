"""
Cryptography Suite - Dark Obsidian & Slate Security Workbench
==============================================================

A complete desktop cryptography application built with customtkinter.
The GUI is fully decoupled from the cryptographic algorithms (which live in
the `algorithms/` package) so each team member can own, explain, and defend
their assigned algorithms during the oral exam.

Run:
    python main.py
"""

import customtkinter as ctk
from tkinter import messagebox
import threading

# ---------------------------------------------------------------------------
# Algorithm registry (GUI layer) - decoupled from the algorithm modules
# ---------------------------------------------------------------------------
from algorithms import (
    member1_alaa as m1,
    member2_ali2 as m2,
    member3_ali_ayman as m3,
    member4_mohammed_ehab as m4,
    member5_omar as m5,
    member6_amr_elshamy as m6,
)

# Each entry:
#   name        - display name
#   module      - algorithm module
#   enc_fn      - encrypt function name
#   dec_fn      - decrypt function name
#   category    - cipher category
#   owner       - team member badge
#   key_fields  - list of (key_name, label, kind) where kind in {"int","text"}
#   formula     - math formula string for the guide box
#   guide       - human-readable key guide
#   rsa         - True for RSA (special key generation flow)
ALGORITHMS = [
    # ---- Member 1: Alaa ----
    {
        "name": "Caesar Cipher",
        "module": m1,
        "enc_fn": "caesar_encrypt",
        "dec_fn": "caesar_decrypt",
        "category": "Substitution",
        "owner": "Alaa (Member 1)",
        "key_fields": [("key", "Shift key (integer)", "int")],
        "formula": "E(x) = (x + key) mod 26    |    D(x) = (x - key) mod 26",
        "guide": "Shift every letter forward by `key` positions (wrap A-Z). "
                 "Any integer works; non-letters pass through unchanged.",
    },
    {
        "name": "Multiplicative Cipher",
        "module": m1,
        "enc_fn": "multiplicative_encrypt",
        "dec_fn": "multiplicative_decrypt",
        "category": "Substitution",
        "owner": "Alaa (Member 1)",
        "key_fields": [("key", "Multiplier key (integer)", "int")],
        "formula": "E(x) = (key * x) mod 26    |    D(x) = (key^-1 * x) mod 26",
        "guide": "Multiply each letter index by `key` mod 26. "
                 "`key` must be coprime to 26 (e.g. 3, 5, 7, 11, 15, 17, 19, 23, 25).",
    },
    {
        "name": "Vernam Cipher",
        "module": m1,
        "enc_fn": "vernam_encrypt",
        "dec_fn": "vernam_decrypt",
        "category": "Symmetric",
        "owner": "Alaa (Member 1)",
        "key_fields": [("key", "Vernam key (text)", "text")],
        "formula": "C = P XOR key (byte-wise, key repeats)",
        "guide": "XOR each byte of the text with the key (key cycles). "
                 "Ciphertext is shown as hex. Encrypt == Decrypt.",
    },
    # ---- Member 2: Ali 2 ----
    {
        "name": "Hill Cipher",
        "module": m2,
        "enc_fn": "hill_encrypt",
        "dec_fn": "hill_decrypt",
        "category": "Polygraphic",
        "owner": "Ali 2 (Member 2)",
        "key_fields": [("key", "4-letter key (2x2 matrix)", "text")],
        "formula": "C = K * P mod 26    |    P = K^-1 * C mod 26",
        "guide": "4-letter key forms a 2x2 matrix. Its determinant must be "
                 "coprime to 26 (e.g. DDCF, ABCY). Spaces are removed.",
    },
    {
        "name": "Playfair Cipher",
        "module": m2,
        "enc_fn": "playfair_encrypt",
        "dec_fn": "playfair_decrypt",
        "category": "Polygraphic",
        "owner": "Ali 2 (Member 2)",
        "key_fields": [("key", "Playfair key (text)", "text")],
        "formula": "Digraph substitution on a 5x5 key table (J merged with I)",
        "guide": "Build a 5x5 table from the key. Same row -> shift right; "
                 "same column -> shift down; rectangle -> swap columns. J = I.",
    },
    # ---- Member 3: Ali Ayman ----
    {
        "name": "Affine Cipher",
        "module": m3,
        "enc_fn": "affine_encrypt",
        "dec_fn": "affine_decrypt",
        "category": "Substitution",
        "owner": "Ali Ayman (Member 3)",
        "key_fields": [("a", "Multiplier 'a' (coprime to 26)", "int"),
                       ("b", "Shift 'b' (integer)", "int")],
        "formula": "E(x) = (a*x + b) mod 26    |    D(x) = a^-1*(x - b) mod 26",
        "guide": "Linear map on letter indices. `a` must be coprime to 26 "
                 "(e.g. 3, 5, 7, 11, 15, 17, 19, 23, 25); `b` is any integer.",
    },
    {
        "name": "DNA Encryption",
        "module": m3,
        "enc_fn": "dna_encrypt",
        "dec_fn": "dna_decrypt",
        "category": "Substitution",
        "owner": "Ali Ayman (Member 3)",
        "key_fields": [("key", "DNA key (text)", "text")],
        "formula": "E(i) = P((i + k) mod 26)    |    D(j) = (P(j) - k) mod 26",
        "guide": "DNA-inspired 5-bit bit-complement substitution (A<->T, C<->G) "
                 "with a Vigenere-style key shift mixed in.",
    },
    # ---- Member 4: Mohammed Ehab ----
    {
        "name": "Vigenere Cipher",
        "module": m4,
        "enc_fn": "vigenere_encrypt",
        "dec_fn": "vigenere_decrypt",
        "category": "Polyalphabetic",
        "owner": "Mohammed Ehab (Member 4)",
        "key_fields": [("key", "Vigenere key (text)", "text")],
        "formula": "E(x_i) = (x_i + k_i) mod 26    |    D(y_i) = (y_i - k_i) mod 26",
        "guide": "Polyalphabetic shift: the key repeats across the message. "
                 "Only letters are encrypted; other characters pass through.",
    },
    {
        "name": "Autokey Cipher",
        "module": m4,
        "enc_fn": "autokey_encrypt",
        "dec_fn": "autokey_decrypt",
        "category": "Polyalphabetic",
        "owner": "Mohammed Ehab (Member 4)",
        "key_fields": [("key", "Autokey primer key (text)", "text")],
        "formula": "Keystream = key || plaintext;  E(x_i) = (x_i + k_i) mod 26",
        "guide": "The keystream starts with the key, then continues with the "
                 "plaintext letters themselves. Stronger than Vigenere.",
    },
    # ---- Member 5: Omar ----
    # ---- Member 5: Omar ----
    {
        "name": "RSA",
        "module": m5,
        "enc_fn": "rsa_encrypt",
        "dec_fn": "rsa_decrypt",
        "category": "Asymmetric",
        "owner": "Omar (Member 5)",
        "key_fields": [("p", "Prime p", "int"),
                       ("q", "Prime q", "int")],
        "formula": "E = m^e mod n    |    D = c^d mod n    (n = p*q)",
        "guide": "Enter two distinct primes p and q to generate keys. "
                 "Encrypt with the public key (e, n); decrypt with the "
                 "private key (d, n). Output is space-separated integers.",
        "rsa": True,
    },
    {
        "name": "Rail Fence Transposition",
        "module": m5,
        "enc_fn": "rail_fence_encrypt",
        "dec_fn": "rail_fence_decrypt",
        "category": "Transposition",
        "owner": "Omar (Member 5)",
        "key_fields": [("rails", "Number of rails (integer)", "int")],
        "formula": "Zig-zag write down/up `rails` rows, then read row by row",
        "guide": "Write the text in a zig-zag across `rails` rails (>=2), "
                 "then read off each row. Spaces are preserved.",
    },
    # Rail Fence Cipher removed - belongs to Omar (Member 5) as his transposition algorithm
    {
        "name": "Single Columnar Transposition",
        "module": m6,
        "enc_fn": "single_columnar_encrypt",
        "dec_fn": "single_columnar_decrypt",
        "category": "Transposition",
        "owner": "Amr Elshamy (Member 6)",
        "key_fields": [("key", "Columnar key (unique letters)", "text")],
        "formula": "Write in rows under key columns; read columns in key order",
        "guide": "Fill a grid row-by-row, then read columns in alphabetical "
                 "order of the key letters. Key must have unique letters.",
    },
    {
        "name": "Double Columnar Transposition",
        "module": m6,
        "enc_fn": "double_columnar_encrypt",
        "dec_fn": "double_columnar_decrypt",
        "category": "Transposition",
        "owner": "Amr Elshamy (Member 6)",
        "key_fields": [("key", "Columnar key (unique letters)", "text")],
        "formula": "Apply Single Columnar transposition twice with the same key",
        "guide": "Single columnar transposition applied two rounds for extra "
                 "diffusion. Key must have unique letters.",
    },
]

# Group algorithms by category for the sidebar.
CATEGORIES = {}
for a in ALGORITHMS:
    CATEGORIES.setdefault(a["category"], []).append(a)

# ---------------------------------------------------------------------------
# Design tokens - Dark Obsidian & Slate Security Workbench
# ---------------------------------------------------------------------------
BG_PRIMARY   = "#0D1117"   # main canvas
BG_PANEL     = "#161B22"   # elevated panels
BG_INPUT     = "#0D1117"   # text areas
BORDER       = "#30363D"   # 1px borders
ACCENT_EMERALD = "#10B981" # primary accent
ACCENT_CYAN    = "#38BDF8" # secondary accent
TEXT_MAIN    = "#F0F6FC"   # primary text
TEXT_DIM     = "#8B949E"   # secondary text
DANGER       = "#F85149"

FONT_UI      = ("Segoe UI", 11)
FONT_UI_BOLD = ("Segoe UI", 11, "bold")
FONT_MONO    = ("Consolas", 12)
FONT_MONO_B  = ("Consolas", 12, "bold")
FONT_HEADER  = ("Segoe UI", 20, "bold")


class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Cryptography Suite - Security Workbench")
        self.geometry("1200x760")
        self.configure(fg_color=BG_PRIMARY)
        ctk.set_appearance_mode("dark")

        self.current_algo = None
        self.rsa_public = None
        self.rsa_private = None

        self._build_layout()
        self._select_first()

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #
    def _build_layout(self):
        # Root grid: sidebar (col 0) | workspace (col 1)
        self.grid_columnconfigure(0, minsize=300)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0,
                                    border_width=1, border_color=BORDER)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_columnconfigure(0, weight=1)
        self.sidebar.grid_rowconfigure(2, weight=1)  # list area expands

        self.workspace = ctk.CTkFrame(self, fg_color=BG_PRIMARY, corner_radius=0)
        self.workspace.grid(row=0, column=1, sticky="nsew")
        self.workspace.grid_columnconfigure(0, weight=1)
        self.workspace.grid_rowconfigure(2, weight=1)  # editor area expands

        self._build_sidebar()
        self._build_workspace()

    # ------------------------------------------------------------------ #
    # Sidebar
    # ------------------------------------------------------------------ #
    def _build_sidebar(self):
        # Header
        header = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(22, 10))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="CRYPTO SUITE", font=FONT_UI_BOLD,
                     text_color=ACCENT_CYAN).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Security Workbench", font=("Segoe UI", 10),
                     text_color=TEXT_DIM).grid(row=1, column=0, sticky="w")

        # Search filter
        ctk.CTkLabel(self.sidebar, text="SEARCH ALGORITHMS", font=("Segoe UI", 10, "bold"),
                     text_color=TEXT_DIM).grid(row=1, column=0, sticky="w", padx=18, pady=(14, 6))
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(self.sidebar, textvariable=self.search_var,
                                         placeholder_text="Filter algorithms...",
                                         fg_color=BG_INPUT, border_color=BORDER,
                                         text_color=TEXT_MAIN, font=FONT_UI,
                                         height=32)
        self.search_entry.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 10))
        self.search_var.trace_add("write", lambda *_: self._rebuild_list())

        # Algorithm list (grouped by category)
        self.list_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent",
                                                 scrollbar_button_color=BORDER,
                                                 scrollbar_button_hover_color=ACCENT_EMERALD)
        self.list_frame.grid(row=3, column=0, sticky="nsew", padx=0, pady=0)
        self.list_frame.grid_columnconfigure(0, weight=1)

        self._rebuild_list()

    def _rebuild_list(self):
        for child in self.list_frame.winfo_children():
            child.destroy()

        query = self.search_var.get().lower()

        for category, algos in CATEGORIES.items():
            # Category divider
            ctk.CTkLabel(self.list_frame, text=category.upper(),
                         font=("Segoe UI", 10, "bold"), text_color=ACCENT_CYAN,
                         anchor="w").grid(sticky="ew", padx=18, pady=(14, 6))

            for algo in algos:
                if query and query not in algo["name"].lower() and query not in algo["owner"].lower():
                    continue
                btn = ctk.CTkButton(self.list_frame, text=algo["name"],
                                    fg_color="transparent", hover_color=BG_INPUT,
                                    text_color=TEXT_MAIN, anchor="w",
                                    font=FONT_UI, height=34, corner_radius=6,
                                    border_width=1, border_color=BORDER,
                                    command=lambda a=algo: self._select_algo(a))
                btn.grid(sticky="ew", padx=14, pady=3)

        # Team member badge (static at bottom)
        badge = ctk.CTkFrame(self.sidebar, fg_color=BG_INPUT, corner_radius=8,
                             border_width=1, border_color=BORDER)
        badge.grid(row=4, column=0, sticky="ew", padx=18, pady=18)
        badge.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(badge, text="TEAM OWNERS", font=("Segoe UI", 9, "bold"),
                     text_color=ACCENT_CYAN).grid(row=0, column=0, sticky="w",
                                                   padx=12, pady=(10, 4))
        owners = ["Alaa  (1)  Caesar, Multiplicative, Vernam",
                  "Ali 2  (2)  Hill, Playfair",
                  "Ali Ayman  (3)  Affine, DNA",
                  "Mohammed Ehab  (4)  Vigenere, Autokey",
                  "Omar  (5)  RSA, Rail Fence Transposition",
                  "Amr Elshamy  (6)  Single & Double Columnar"]
        for i, o in enumerate(owners):
            ctk.CTkLabel(badge, text=o, font=("Consolas", 9), text_color=TEXT_DIM,
                         anchor="w").grid(row=i + 1, column=0, sticky="w",
                                           padx=16, pady=1)
        ctk.CTkLabel(badge, text="", height=2).grid(row=len(owners) + 1, column=0, pady=(0, 8))

    def _select_first(self):
        # pick first visible algorithm
        first = None
        for category, algos in CATEGORIES.items():
            if algos:
                first = algos[0]
                break
        if first:
            self._select_algo(first)

    def _select_algo(self, algo):
        self.current_algo = algo
        self.rsa_public = None
        self.rsa_private = None
        self._render_workspace()

    # ------------------------------------------------------------------ #
    # Workspace
    # ------------------------------------------------------------------ #
    def _build_workspace(self):
        # Header strip
        self.header_frame = ctk.CTkFrame(self.workspace, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=26, pady=(22, 10))
        self.header_frame.grid_columnconfigure(1, weight=1)

        self.lbl_name = ctk.CTkLabel(self.header_frame, text="", font=FONT_HEADER,
                                     text_color=TEXT_MAIN, anchor="w")
        self.lbl_name.grid(row=0, column=0, sticky="w")

        self.lbl_meta = ctk.CTkLabel(self.header_frame, text="", font=("Segoe UI", 11),
                                     text_color=TEXT_DIM, anchor="w")
        self.lbl_meta.grid(row=1, column=0, sticky="w")

        # Owner badge at right of header
        self.lbl_owner = ctk.CTkLabel(self.header_frame, text="", font=FONT_UI_BOLD,
                                      text_color=ACCENT_EMERALD)
        self.lbl_owner.grid(row=0, column=1, rowspan=2, sticky="e")

        # Formula & Key Guide box
        self.guide_box = ctk.CTkFrame(self.workspace, fg_color=BG_PANEL,
                                      corner_radius=10, border_width=1,
                                      border_color=BORDER)
        self.guide_box.grid(row=1, column=0, sticky="ew", padx=26, pady=(0, 14))
        self.guide_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.guide_box, text="FORMULA & KEY GUIDE", font=("Segoe UI", 10, "bold"),
                     text_color=ACCENT_CYAN).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        self.lbl_formula = ctk.CTkLabel(self.guide_box, text="", font=FONT_MONO,
                                        text_color=ACCENT_CYAN, anchor="w", justify="left")
        self.lbl_formula.grid(row=1, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 2))
        self.lbl_guide = ctk.CTkLabel(self.guide_box, text="", font=("Segoe UI", 10.5),
                                      text_color=TEXT_DIM, anchor="w", justify="left",
                                      wraplength=700)
        self.lbl_guide.grid(row=2, column=0, columnspan=2, sticky="ew", padx=16, pady=(2, 12))

        # Dynamic key input panel
        self.key_panel = ctk.CTkFrame(self.workspace, fg_color=BG_PANEL,
                                      corner_radius=10, border_width=1,
                                      border_color=BORDER)
        self.key_panel.grid(row=2, column=0, sticky="ew", padx=26, pady=(0, 14))
        self.key_panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.key_panel, text="KEY INPUT", font=("Segoe UI", 10, "bold"),
                     text_color=ACCENT_CYAN).grid(row=0, column=0, columnspan=3,
                                                   sticky="w", padx=16, pady=(12, 10))

        self.key_entries = {}   # key_name -> CTkEntry

        # Editors area (row 3 expands)
        self.editor_frame = ctk.CTkFrame(self.workspace, fg_color="transparent")
        self.editor_frame.grid(row=4, column=0, sticky="nsew", padx=26, pady=(0, 10))
        self.editor_frame.grid_columnconfigure(0, weight=1)
        self.editor_frame.grid_columnconfigure(1, weight=1)
        self.editor_frame.grid_rowconfigure(1, weight=1)

        # Input label + text
        self.lbl_input = ctk.CTkLabel(self.editor_frame, text="INPUT PLAINTEXT",
                                      font=("Segoe UI", 11, "bold"), text_color=TEXT_MAIN)
        self.lbl_input.grid(row=0, column=0, sticky="w", padx=(0, 12), pady=(0, 6))

        self.txt_input = ctk.CTkTextbox(self.editor_frame, fg_color=BG_INPUT,
                                        border_color=BORDER, border_width=1,
                                        font=FONT_MONO, text_color=TEXT_MAIN,
                                        activate_scrollbars=True)
        self.txt_input.grid(row=1, column=0, sticky="nsew", padx=(0, 12))

        # Output label + text
        self.lbl_output = ctk.CTkLabel(self.editor_frame, text="OUTPUT CIPHERTEXT",
                                       font=("Segoe UI", 11, "bold"), text_color=TEXT_MAIN)
        self.lbl_output.grid(row=0, column=1, sticky="w", padx=(12, 0), pady=(0, 6))

        self.txt_output = ctk.CTkTextbox(self.editor_frame, fg_color=BG_INPUT,
                                         border_color=BORDER, border_width=1,
                                         font=FONT_MONO, text_color=ACCENT_CYAN,
                                         activate_scrollbars=True)
        self.txt_output.grid(row=1, column=1, sticky="nsew", padx=(12, 0))

        # Button row
        self.btn_row = ctk.CTkFrame(self.workspace, fg_color="transparent")
        self.btn_row.grid(row=5, column=0, sticky="ew", padx=26, pady=(0, 22))
        self.btn_row.grid_columnconfigure(0, weight=1)

        self.btn_encrypt = ctk.CTkButton(self.btn_row, text="ENCRYPT",
                                         fg_color=ACCENT_EMERALD, hover_color="#0E7A61",
                                         text_color="#051A14", font=FONT_UI_BOLD,
                                         height=38, corner_radius=6,
                                         command=self._do_encrypt)
        self.btn_encrypt.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.btn_decrypt = ctk.CTkButton(self.btn_row, text="DECRYPT",
                                         fg_color=ACCENT_CYAN, hover_color="#0E7A61",
                                         text_color="#051A14", font=FONT_UI_BOLD,
                                         height=38, corner_radius=6,
                                         command=self._do_decrypt)
        self.btn_decrypt.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.btn_swap = ctk.CTkButton(self.btn_row, text="SWAP (Output -> Input)",
                                      fg_color="transparent", border_color=ACCENT_CYAN,
                                      border_width=1, text_color=ACCENT_CYAN,
                                      font=FONT_UI_BOLD, height=38, corner_radius=6,
                                      command=self._do_swap)
        self.btn_swap.grid(row=0, column=2, sticky="ew", padx=(0, 8))

        self.btn_copy = ctk.CTkButton(self.btn_row, text="COPY OUTPUT",
                                      fg_color="transparent", border_color=BORDER,
                                      border_width=1, text_color=TEXT_MAIN,
                                      font=FONT_UI_BOLD, height=38, corner_radius=6,
                                      command=self._do_copy)
        self.btn_copy.grid(row=0, column=3, sticky="ew", padx=(0, 8))

        self.btn_clear = ctk.CTkButton(self.btn_row, text="CLEAR ALL",
                                       fg_color="transparent", border_color=DANGER,
                                       border_width=1, text_color=DANGER,
                                       font=FONT_UI_BOLD, height=38, corner_radius=6,
                                       command=self._do_clear)
        self.btn_clear.grid(row=0, column=4, sticky="ew")

        self.btn_sample = ctk.CTkButton(self.workspace, text="LOAD SAMPLE INPUT",
                                        fg_color=BG_INPUT, border_color=BORDER,
                                        border_width=1, text_color=TEXT_MAIN,
                                        font=FONT_UI_BOLD, height=32, corner_radius=6,
                                        command=self._do_sample)
        self.btn_sample.grid(row=6, column=0, sticky="e", padx=26, pady=(0, 18))

        # Status bar
        self.status = ctk.CTkLabel(self.workspace, text="Ready", font=("Segoe UI", 10),
                                   text_color=TEXT_DIM, anchor="w")
        self.status.grid(row=7, column=0, sticky="ew", padx=26, pady=(0, 10))

    def _render_workspace(self):
        algo = self.current_algo
        self.lbl_name.configure(text=algo["name"])
        self.lbl_meta.configure(text=f"{algo['category']}   •   Ciphersuite")
        self.lbl_owner.configure(text=algo["owner"])
        self.lbl_formula.configure(text=algo["formula"])
        self.lbl_guide.configure(text=algo["guide"])

        # Rebuild key inputs
        for child in self.key_panel.winfo_children():
            child.destroy()

        ctk.CTkLabel(self.key_panel, text="KEY INPUT", font=("Segoe UI", 10, "bold"),
                     text_color=ACCENT_CYAN).grid(row=0, column=0, columnspan=3,
                                                   sticky="w", padx=16, pady=(12, 10))
        self.key_entries = {}
        row = 1
        if algo.get("rsa"):
            ctk.CTkLabel(self.key_panel, text="Generate RSA keys from two primes:",
                         font=("Segoe UI", 10), text_color=TEXT_DIM).grid(
                             row=row, column=0, sticky="w", padx=16, pady=(0, 6))
            row += 1

        for key_name, label, kind in algo["key_fields"]:
            ctk.CTkLabel(self.key_panel, text=label, font=("Segoe UI", 10.5),
                         text_color=TEXT_MAIN).grid(row=row, column=0, sticky="w",
                                                     padx=16, pady=7)
            ent = ctk.CTkEntry(self.key_panel, fg_color=BG_INPUT,
                               border_color=BORDER, text_color=TEXT_MAIN,
                               font=FONT_MONO, height=30)
            ent.grid(row=row, column=1, sticky="ew", padx=16, pady=7)
            self.key_entries[key_name] = ent
            row += 1

        if algo.get("rsa"):
            self.btn_rsa_gen = ctk.CTkButton(self.key_panel, text="GENERATE RSA KEYS",
                                             fg_color=ACCENT_EMERALD,
                                             hover_color="#0E7A61",
                                             text_color="#051A14",
                                             font=FONT_UI_BOLD, height=30,
                                             command=self._do_rsa_gen)
            self.btn_rsa_gen.grid(row=row, column=0, columnspan=2, sticky="ew",
                                  padx=16, pady=(10, 12))
            self.lbl_rsa_keys = ctk.CTkLabel(self.key_panel, text="",
                                             font=("Consolas", 9), text_color=TEXT_DIM,
                                             anchor="w", justify="left")
            self.lbl_rsa_keys.grid(row=row + 1, column=0, columnspan=2, sticky="ew",
                                   padx=16, pady=(0, 12))
        else:
            ctk.CTkLabel(self.key_panel, text="",
                         height=10).grid(row=row, column=0, pady=(0, 12))

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #
    def _get_text(self, widget):
        return widget.get("1.0", "end").rstrip("\n")

    def _set_text(self, widget, text):
        widget.delete("1.0", "end")
        widget.insert("1.0", text)

    def _gather_keys(self):
        """Read and validate key inputs for the active algorithm."""
        algo = self.current_algo
        if algo.get("rsa"):
            p = self.key_entries["p"].get().strip()
            q = self.key_entries["q"].get().strip()
            if not p or not q:
                raise ValueError("Enter both prime p and prime q.")
            pub, priv = m5.rsa_generate_keys(p, q)
            self.rsa_public = pub
            self.rsa_private = priv
            self.lbl_rsa_keys.configure(
                text=f"Public key  (e, n) = {pub}    |    Private key  (d, n) = {priv}")
            return None  # key handled via self.rsa_*
        kwargs = {}
        # Map algorithm function parameter names to key_fields names.
        # Caesar's key_fields labels the parameter as "key" but the function
        # expects "shift"; all other algorithms match by default.
        param_rename = {
            "Caesar Cipher": "shift",
        }
        expected_param = param_rename.get(algo["name"])
        for key_name, _, kind in algo["key_fields"]:
            val = self.key_entries[key_name].get().strip()
            if val == "":
                raise ValueError(f"Please enter the {key_name}.")
            if kind == "int":
                try:
                    kwargs[expected_param if expected_param else key_name] = int(val)
                except ValueError:
                    raise ValueError(f"'{key_name}' must be an integer, got {val!r}.")
            else:
                kwargs[expected_param if expected_param else key_name] = val
        return kwargs

    def _do_rsa_gen(self):
        """Explicitly generate RSA keys from prime p and q inputs with timeout guard."""
        try:
            p = self.key_entries["p"].get().strip()
            q = self.key_entries["q"].get().strip()
            if not p or not q:
                raise ValueError("Enter both prime p and prime q.")

            # Run the blocking key generation in a thread with a timeout
            result = [None]
            error = [None]

            def run_gen():
                try:
                    pub, priv = m5.rsa_generate_keys(p, q)
                    result[0] = (pub, priv)
                except Exception as e:
                    error[0] = e

            thread = threading.Thread(target=run_gen, daemon=True)
            thread.start()
            thread.join(timeout=10)  # 10-second timeout

            if thread.is_alive():
                # Thread is still running — timeout
                messagebox.showerror("Key Generation Timeout",
                    "RSA key generation took too long (10s). "
                    "This may be caused by very large primes or an infinite loop. "
                    "Try smaller prime values.")
                self.status.configure(text="RSA key generation timed out.", text_color=DANGER)
                return

            if error[0] is not None:
                raise error[0]

            pub, priv = result[0]
            self.rsa_public = pub
            self.rsa_private = priv
            self.lbl_rsa_keys.configure(
                text=f"Public key  (e, n) = {pub}    |    Private key  (d, n) = {priv}")
            self.status.configure(text="RSA keys generated successfully.", text_color=ACCENT_EMERALD)
        except ValueError as ve:
            messagebox.showerror("Key Generation Error", str(ve))
        except Exception as exc:
            messagebox.showerror("Key Generation Error", str(exc))

    def _do_encrypt(self):
        try:
            algo = self.current_algo
            pt = self._get_text(self.txt_input)
            if not pt:
                self.status.configure(text="Enter some text to encrypt.", text_color=TEXT_DIM)
                return

            if algo.get("rsa"):
                if self.rsa_public is None:
                    self._gather_keys()
                kwargs = {"public_key": self.rsa_public}
            else:
                kwargs = self._gather_keys()

            # Run encryption in a thread with a timeout to prevent GUI freeze
            result = [None]
            error = [None]

            def run_enc():
                try:
                    enc_fn = getattr(algo["module"], algo["enc_fn"])
                    ct = enc_fn(pt, **kwargs)
                    result[0] = ct
                except Exception as e:
                    error[0] = e

            thread = threading.Thread(target=run_enc, daemon=True)
            thread.start()
            thread.join(timeout=10)  # 10-second timeout

            if thread.is_alive():
                messagebox.showerror("Encryption Timeout",
                    "Encryption took too long (10s). The operation may be looping or "
                    "involving very large data. Try shorter text or smaller keys.")
                self.status.configure(text="Encryption timed out.", text_color=DANGER)
                return

            if error[0] is not None:
                raise error[0]

            ct = result[0]
            self._set_text(self.txt_output, ct)
            self.status.configure(text="Encrypted successfully.", text_color=ACCENT_EMERALD)
        except Exception as exc:
            messagebox.showerror("Encryption Error", str(exc))

    def _do_decrypt(self):
        try:
            algo = self.current_algo
            ct = self._get_text(self.txt_input)
            if not ct:
                self.status.configure(text="Enter some text to decrypt.", text_color=TEXT_DIM)
                return

            if algo.get("rsa"):
                if self.rsa_private is None:
                    self._gather_keys()
                kwargs = {"private_key": self.rsa_private}
            else:
                kwargs = self._gather_keys()

            # Run decryption in a thread with a timeout to prevent GUI freeze
            result = [None]
            error = [None]

            def run_dec():
                try:
                    dec_fn = getattr(algo["module"], algo["dec_fn"])
                    pt = dec_fn(ct, **kwargs)
                    result[0] = pt
                except Exception as e:
                    error[0] = e

            thread = threading.Thread(target=run_dec, daemon=True)
            thread.start()
            thread.join(timeout=10)  # 10-second timeout

            if thread.is_alive():
                messagebox.showerror("Decryption Timeout",
                    "Decryption took too long (10s). The operation may be looping or "
                    "involving very large ciphertext. Try shorter data or smaller keys.")
                self.status.configure(text="Decryption timed out.", text_color=DANGER)
                return

            if error[0] is not None:
                raise error[0]

            pt = result[0]
            self._set_text(self.txt_output, pt)
            self.status.configure(text="Decrypted successfully.", text_color=ACCENT_EMERALD)
        except Exception as exc:
            messagebox.showerror("Decryption Error", str(exc))

    def _do_swap(self):
        """Copy output into input so you can immediately test decryption."""
        out = self._get_text(self.txt_output)
        self._set_text(self.txt_input, out)
        self.status.configure(text="Output swapped into input.", text_color=ACCENT_CYAN)

    def _do_copy(self):
        out = self._get_text(self.txt_output)
        if out:
            self.clipboard_clear()
            self.clipboard_append(out)
            self.status.configure(text="Output copied to clipboard.", text_color=ACCENT_CYAN)

    def _do_clear(self):
        self._set_text(self.txt_input, "")
        self._set_text(self.txt_output, "")
        self.status.configure(text="Cleared.", text_color=TEXT_DIM)

    def _do_sample(self):
        samples = {
            "Caesar Cipher": "Hello World 2026!",
            "Multiplicative Cipher": "Attack at dawn",
            "Vernam Cipher": "Secret Message",
            "Hill Cipher": "HELLO WORLD",
            "Playfair Cipher": "Hide the gold",
            "Affine Cipher": "Affine Cipher",
            "DNA Encryption": "DNA Test",
            "Vigenere Cipher": "Vigenere Cipher",
            "Autokey Cipher": "Autokey Test",
            "RSA": "RSA TEST",
            "Rail Fence Cipher": "Rail Fence Cipher",
            "Single Columnar Transposition": "Single Columnar",
            "Double Columnar Transposition": "Double Columnar",
        }
        name = self.current_algo["name"]
        text = samples.get(name, "Sample plaintext for testing.")
        self._set_text(self.txt_input, text)
        self.status.configure(text=f"Sample input loaded for {name}.", text_color=ACCENT_CYAN)


def main():
    app = CryptoApp()
    app.mainloop()


if __name__ == "__main__":
    main()
