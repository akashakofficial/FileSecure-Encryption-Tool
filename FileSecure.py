import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox

# Generate a random salt
def generate_salt():
    return os.urandom(16)  # 16 bytes salt

# Key Derivation Function (KDF) using PBKDF2
def derive_key(password, salt, iterations=100000):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)

# Encrypt the file content using buffered reading/writing
def encrypt_content(input_file, output_file, password):
    salt = generate_salt()  # Generate a random salt
    key = derive_key(password, salt)  # Derive key from password and salt

    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        f_out.write(salt)  # Prepend salt to the encrypted content
        while True:
            chunk = f_in.read(4096)  # Read in 4KB chunks
            if not chunk:
                break
            
            encrypted_chunk = bytearray()
            for i, byte in enumerate(chunk):
                key_byte = key[i % len(key)]  # Loop over the derived key
                # Shift byte based on the key
                encrypted_byte = (byte + key_byte) % 256
                encrypted_chunk.append(encrypted_byte)
            f_out.write(encrypted_chunk)

# Decrypt the file content using buffered reading/writing
def decrypt_content(input_file, output_file, password):
    with open(input_file, "rb") as f_in:
        salt = f_in.read(16)  # Extract the salt (first 16 bytes)
        key = derive_key(password, salt)  # Derive key from password and salt
        
        with open(output_file, "wb") as f_out:
            while True:
                chunk = f_in.read(4096)  # Read in 4KB chunks
                if not chunk:
                    break
                
                decrypted_chunk = bytearray()
                for i, byte in enumerate(chunk):
                    key_byte = key[i % len(key)]  # Loop over the derived key
                    decrypted_byte = (byte - key_byte) % 256  # Reverse the shift
                    decrypted_chunk.append(decrypted_byte)
                f_out.write(decrypted_chunk)

# Process the selected file for encryption
def process_file(input_file, password):
    save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
    if save_path:
        encrypt_content(input_file, save_path, password)
        messagebox.showinfo("Success", f"File has been encrypted successfully and saved to {save_path}.")
        status_label.config(text="Process completed successfully.", foreground="#4CAF50")
        progress_canvas.delete("progress_arc")

        # Clear selected file and password entries
        encryption_file_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        selected_file.set("")

# Decrypt the selected text file
def decrypt_file(encrypted_file, password):
    save_path = filedialog.asksaveasfilename(defaultextension=".*", filetypes=[("All files", "*.*")])
    if save_path:
        decrypt_content(encrypted_file, save_path, password)
        messagebox.showinfo("Success", "Decryption completed successfully.")
        status_label.config(text="Decryption completed successfully.", foreground="#4CAF50")
        progress_canvas.delete("progress_arc")

        # Clear selected file and password entries
        decryption_file_entry.delete(0, tk.END)  # Clear the encrypted file entry
        password_entry.delete(0, tk.END)          # Clear the password entry
        selected_file.set("")                      # Clear the selected file variable

# Update UI after file selection for encryption
def on_select_file():
    input_file = filedialog.askopenfilename(title="Select File for Encryption", filetypes=[("All Files", "*.*")])
    if input_file:
        encryption_file_entry.delete(0, tk.END)
        encryption_file_entry.insert(0, input_file)
        status_label.config(text="", foreground="#757575")
        selected_file.set(input_file)
    else:
        status_label.config(text="No file selected", foreground="#F44336")

# Update UI after encrypted file selection for decryption
def on_select_encrypted_file():
    encrypted_file = filedialog.askopenfilename(title="Select Encrypted File for Decryption", filetypes=[("Encrypted files", "*.enc")])
    if encrypted_file:
        decryption_file_entry.delete(0, tk.END)
        decryption_file_entry.insert(0, encrypted_file)
        status_label.config(text="", foreground="#757575")
        selected_file.set(encrypted_file)
    else:
        status_label.config(text="No file selected", foreground="#F44336")

# Process the file with the password for encryption
def save_file():
    input_file = selected_file.get()
    password = password_entry.get()
    if input_file and password and len(password) >= 12:
        status_label.config(text="Encrypting file...", foreground="blue")
        animate_progress()
        app.after(100, process_file, input_file, password)
    else:
        status_label.config(text="Select a file and ensure password is at least 12 characters long.", foreground="#F44336")

# Decrypt the file with the password
def decrypt_encrypted_file():
    encrypted_file = selected_file.get()
    password = password_entry.get()
    if encrypted_file and password and len(password) >= 12:
        status_label.config(text="Decrypting file...", foreground="blue")
        animate_progress()
        app.after(100, decrypt_file, encrypted_file, password)
    else:
        status_label.config(text="Select an encrypted file and ensure password is at least 12 characters long.", foreground="#F44336")

# Animated circular progress indicator
def animate_progress():
    progress_canvas.delete("progress_arc")
    for i in range(0, 360, 10):
        progress_canvas.create_arc(25, 25, 75, 75, start=0, extent=i, outline="#FF5722", width=8, style="arc", tags="progress_arc")
        app.update_idletasks()
        progress_canvas.after(25)

# Function to show the main page
def show_main_page():
    for widget in app.winfo_children():
        widget.destroy()

    # Card-style frame for containing widgets
    card_frame = tk.Frame(app, bg="#7D97F4", bd=2, relief="raised")
    card_frame.place(relx=0.5, rely=0.5, anchor="center", width=800, height=500)

    # Title
    title_label = tk.Label(card_frame, text="FileSecure", font=("Times New Roman", 40, "bold"), bg="#7D97F4", fg="#FFFFFF")
    title_label.pack(pady=20)

    # Description
    description_label = tk.Label(card_frame, text="FileSecure is a tool for encrypting and decrypting files using a secure password.", font=("Times New Roman", 14), bg="#7D97F4", fg="#FFFFFF", wraplength=700, justify="center")
    description_label.pack(pady=10)

    # Button frame
    button_frame = tk.Frame(card_frame, bg="#7D97F4")
    button_frame.pack(pady=20)

    # Larger Encrypt button
    encrypt_button = tk.Button(
        button_frame, 
        text="Encrypt", 
        command=show_encryption_page,
        bg="#FE7062", 
        fg="#FFFFFF", 
        font=("Times New Roman", 16, "bold"), 
        padx=20, 
        pady=15,  
        width=12,  
        height=2,  
        bd=0, 
        relief="ridge"
    )
    encrypt_button.grid(row=0, column=0, padx=10)

    # Larger Decrypt button
    decrypt_button = tk.Button(
        button_frame, 
        text="Decrypt", 
        command=show_decryption_page,
        bg="#FE7062", 
        fg="#FFFFFF", 
        font=("Times New Roman", 16, "bold"),  
        padx=20, 
        pady=15,  
        width=12,  
        height=2,  
        bd=0, 
        relief="ridge"
    )
    decrypt_button.grid(row=0, column=1, padx=10)

# Function to show the encryption page
def show_encryption_page():
    for widget in app.winfo_children():
        widget.destroy()

    # Card-style frame for containing widgets
    card_frame = tk.Frame(app, bg="#FFFFFF", bd=2, relief="raised")
    card_frame.place(relx=0.5, rely=0.5, anchor="center", width=800, height=500)

    # Title
    title_label = tk.Label(card_frame, text="FileSecure Encrypter", font=("Times New Roman", 25, "bold"), bg="#FFFFFF", fg="#3E50B4")
    title_label.pack(pady=20)

    # File selection frame
    file_frame = tk.Frame(card_frame, bg="#FFFFFF")
    file_frame.pack(pady=10)

    select_file_btn = tk.Button(file_frame, text="Select File for Encryption", command=on_select_file, bg="#0066FF", fg="#FFFFFF", font=("Times New Roman", 14, "bold"), padx=10, pady=5, bd=0, relief="groove")
    select_file_btn.grid(row=0, column=0, padx=5)

    global encryption_file_entry
    encryption_file_entry = tk.Entry(file_frame, bg="#FFFFFF", fg="#000000", font=("Times New Roman", 14), width=40, borderwidth=2)
    encryption_file_entry.grid(row=0, column=1, padx=5)

    # Password frame
    password_frame = tk.Frame(card_frame, bg="#FFFFFF")
    password_frame.pack(pady=10)

    password_label = tk.Label(password_frame, text="Enter Password (min 12 chars):", font=("Times New Roman", 14), bg="#FFFFFF", fg="#000000")
    password_label.grid(row=0, column=0)

    global password_entry
    password_entry = tk.Entry(password_frame, show="*", bg="#FFFFFF", fg="#000000", font=("Times New Roman", 14), borderwidth=2)
    password_entry.grid(row=0, column=1)

    # Checkbox for show/hide password
    global show_password_var
    show_password_var = tk.BooleanVar(value=False)  # Default is hidden

    toggle_password_checkbox = tk.Checkbutton(
        password_frame, 
        text="Show Password", 
        variable=show_password_var, 
        bg="#FFFFFF", 
        command=lambda: toggle_password_visibility()
    )
    toggle_password_checkbox.grid(row=0, column=2, padx=(5, 0))

    # Button frame for Encrypt and Back buttons
    button_frame = tk.Frame(card_frame, bg="#FFFFFF")
    button_frame.pack(pady=20)

    back_button = tk.Button(button_frame, text=" Back ", command=show_main_page, bg="#FF9800", fg="#FFFFFF", font=("Times New Roman", 16, "bold"), padx=20, pady=10, bd=0, relief="ridge")
    back_button.grid(row=0, column=0, padx=10)

    save_file_btn = tk.Button(button_frame, text="Encrypt File", command=save_file, bg="#4CAF50", fg="#FFFFFF", font=("Times New Roman", 16, "bold"), padx=20, pady=10, bd=0, relief="ridge")
    save_file_btn.grid(row=0, column=1, padx=10)

    # Status label
    global status_label
    status_label = tk.Label(card_frame, text="", font=("Times New Roman", 14), bg="#FFFFFF", fg="#F44336")
    status_label.pack(pady=10)

    # Progress indicator
    global progress_canvas
    progress_canvas = tk.Canvas(card_frame, width=100, height=100, bg="#FFFFFF", highlightthickness=0)
    progress_canvas.pack(pady=20)

# Function to toggle password visibility
def toggle_password_visibility():
    if show_password_var.get():  # Show password
        password_entry.config(show="")
    else:  # Hide password
        password_entry.config(show="*")

# Function to show the decryption page
def show_decryption_page():
    for widget in app.winfo_children():
        widget.destroy()

    # Card-style frame for containing widgets
    card_frame = tk.Frame(app, bg="#FFFFFF", bd=2, relief="raised")
    card_frame.place(relx=0.5, rely=0.5, anchor="center", width=800, height=500)

    # Title
    title_label = tk.Label(card_frame, text="FileSecure Decrypter", font=("Times New Roman", 25, "bold"), bg="#FFFFFF", fg="#3E50B4")
    title_label.pack(pady=20)

    # Encrypted file selection frame
    encrypted_file_frame = tk.Frame(card_frame, bg="#FFFFFF")
    encrypted_file_frame.pack(pady=10)

    select_encrypted_file_btn = tk.Button(encrypted_file_frame, text="Select Encrypted File", command=on_select_encrypted_file, bg="#0066FF", fg="#FFFFFF", font=("Times New Roman", 14, "bold"), padx=10, pady=5, bd=0, relief="groove")
    select_encrypted_file_btn.grid(row=0, column=0, padx=5)

    global decryption_file_entry
    decryption_file_entry = tk.Entry(encrypted_file_frame, bg="#FFFFFF", fg="#000000", font=("Times New Roman", 14), width=40, borderwidth=2)
    decryption_file_entry.grid(row=0, column=1, padx=5)

    # Password frame
    password_frame = tk.Frame(card_frame, bg="#FFFFFF")
    password_frame.pack(pady=10)

    password_label = tk.Label(password_frame, text="Enter Password (min 12 chars):", font=("Times New Roman", 14), bg="#FFFFFF", fg="#000000")
    password_label.grid(row=0, column=0)

    global password_entry
    password_entry = tk.Entry(password_frame, show="*", bg="#FFFFFF", fg="#000000", font=("Times New Roman", 14), borderwidth=2)
    password_entry.grid(row=0, column=1)

    # Checkbox for show/hide password
    global show_password_var
    show_password_var = tk.BooleanVar(value=False)  # Default is hidden

    toggle_password_checkbox = tk.Checkbutton(
        password_frame, 
        text="Show Password", 
        variable=show_password_var, 
        bg="#FFFFFF", 
        command=lambda: toggle_password_visibility()
    )
    toggle_password_checkbox.grid(row=0, column=2, padx=(5, 0))

    # Button frame for Decrypt and Back buttons
    button_frame = tk.Frame(card_frame, bg="#FFFFFF")
    button_frame.pack(pady=20)

    back_button = tk.Button(button_frame, text=" Back ", command=show_main_page, bg="#FF9800", fg="#FFFFFF", font=("Times New Roman", 16, "bold"), padx=20, pady=10, bd=0, relief="ridge")
    back_button.grid(row=0, column=0, padx=10)

    decrypt_file_btn = tk.Button(button_frame, text="Decrypt File", command=decrypt_encrypted_file, bg="#4CAF50", fg="#FFFFFF", font=("Times New Roman", 16, "bold"), padx=20, pady=10, bd=0, relief="ridge")
    decrypt_file_btn.grid(row=0, column=1, padx=10)

    # Status label
    global status_label
    status_label = tk.Label(card_frame, text="", font=("Times New Roman", 14), bg="#FFFFFF", fg="#F44336")
    status_label.pack(pady=10)

    # Progress indicator
    global progress_canvas
    progress_canvas = tk.Canvas(card_frame, width=100, height=100, bg="#FFFFFF", highlightthickness=0)
    progress_canvas.pack(pady=20)

# Create the main application window
app = tk.Tk()
app.title("FileSecure")
app.geometry("800x500")
app.resizable(False, False)

# Initialize the selected file variable
selected_file = tk.StringVar()

# Start with the main page
show_main_page()

# Run the application
app.mainloop()
