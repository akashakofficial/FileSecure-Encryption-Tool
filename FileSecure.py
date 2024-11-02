import random
import numpy as np
import math
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

# Generate a hash value from the password
def hash_password(password):
    sha256_hash = hashlib.sha256(password.encode()).digest()
    base64_hash = base64.b64encode(sha256_hash).decode('utf-8')
    while len(base64_hash) < 2048:
        sha256_hash = hashlib.sha256(base64_hash.encode()).digest()
        base64_hash += base64.b64encode(sha256_hash).decode('utf-8')
    return base64_hash[:2048]

# Process the selected file for encryption
def process_file(input_file, password):
    with open(input_file, "rb") as f:
        file_content = f.read()
    base64_content = base64.b64encode(file_content).decode('utf-8')
    length = len(base64_content)
    array1 = list(base64_content)
    hashed_password = hash_password(password)
    array2 = list(hashed_password)
    result_array = [''] * length
    for i in range(length):
        if i % 2048 == 0 and i != 0:
            hashed_password = hash_password(password)
            array2 = list(hashed_password)
        char1 = array1[i]
        char2 = array2[i % 2048]
        x = ord(char1)
        y = ord(char2)
        resultant_ascii = (((x - 33) + (y - 33)) % 93) + 33
        result_char = chr(resultant_ascii)
        result_array[i] = result_char
    save_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
    if save_path:
        save_to_file(save_path, ''.join(result_array))
        messagebox.showinfo("Success", f"File has been saved successfully at {save_path}.")
        status_label.config(text="Process completed successfully.", foreground="#4CAF50")
        progress_canvas.delete("progress_arc")

# Save content to a file
def save_to_file(filename, content):
    with open(filename, "w") as f:
        f.write(content)

# Decrypt the selected text file
def decrypt_file(encrypted_file, password):
    with open(encrypted_file, "r") as f:
        result_array = list(f.read().strip())
    length = len(result_array)
    decrypted_x_array = [''] * length
    hashed_password = hash_password(password)
    array2 = list(hashed_password)
    for i in range(length):
        if i % 2048 == 0 and i != 0:
            hashed_password = hash_password(password)
            array2 = list(hashed_password)
        char_num1 = result_array[i]
        char2 = array2[i % 2048]
        num1 = ord(char_num1)
        y = ord(char2)
        x = (((num1 - 33) - (y - 33)) % 93) + 33
        decrypted_x_array[i] = chr(x)
    base64_content = ''.join(decrypted_x_array)
    file_content = base64.b64decode(base64_content)
    save_path = filedialog.asksaveasfilename(defaultextension=".*", filetypes=[("All files", "*.*")])
    if save_path:
        with open(save_path, "wb") as f:
            f.write(file_content)
        messagebox.showinfo("Success", "Decryption completed successfully.")
        status_label.config(text="Decryption completed successfully.", foreground="#4CAF50")
        progress_canvas.delete("progress_arc")

# Update UI after file selection for encryption
def on_select_file():
    input_file = filedialog.askopenfilename(title="Select File for Encryption", filetypes=[("All Files", "*.*")])
    if input_file:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, input_file)
        status_label.config(text="", foreground="#757575")
        selected_file.set(input_file)
    else:
        status_label.config(text="No file selected", foreground="#F44336")

# Update UI after encrypted file selection for decryption
def on_select_encrypted_file():
    encrypted_file = filedialog.askopenfilename(title="Select Encrypted File for Decryption", filetypes=[("Binary files", "*.bin")])
    if encrypted_file:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, encrypted_file)
        status_label.config(text="", foreground="#757575")
        selected_file.set(encrypted_file)
    else:
        status_label.config(text="No file selected", foreground="#F44336")

# Process the file with the password for encryption
def save_file():
    input_file = selected_file.get()
    password = password_entry.get()
    if input_file and password and len(password) >= 12:
        status_label.config(text="Processing file...", foreground="blue")
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
    card_frame = tk.Frame(app, bg="#FFFFFF", bd=2, relief="raised")
    card_frame.place(relx=0.5, rely=0.5, anchor="center", width=800, height=500)

    # Title
    title_label = tk.Label(card_frame, text="FileSecure", font=("Times New Roman", 30, "bold"), bg="#FFFFFF", fg="#3E50B4")
    title_label.pack(pady=20)

    # Description
    description_label = tk.Label(card_frame, text="FileSecure is a tool for encrypting and decrypting files using a secure password. Ensure your password is at least 12 characters long for optimal security.", font=("Times New Roman", 14), bg="#FFFFFF", fg="#757575", wraplength=700, justify="center")
    description_label.pack(pady=10)

    # Button frame
    button_frame = tk.Frame(card_frame, bg="#FFFFFF")
    button_frame.pack(pady=20)

    # Larger Encrypt button
    encrypt_button = tk.Button(
        button_frame, 
        text="Encrypt", 
        command=show_encryption_page,
        bg="#0066FF", 
        fg="#FFFFFF", 
        font=("Times New Roman", 16, "bold"),  # Increased font size
        padx=20, 
        pady=15,  # Increased padding
        width=12,  # Set fixed width
        height=2,  # Set fixed height
        bd=0, 
        relief="ridge"
    )
    encrypt_button.grid(row=0, column=0, padx=10)

    # Larger Decrypt button
    decrypt_button = tk.Button(
        button_frame, 
        text="Decrypt", 
        command=show_decryption_page,
        bg="#0066FF", 
        fg="#FFFFFF", 
        font=("Times New Roman", 16, "bold"),  # Increased font size
        padx=20, 
        pady=15,  # Increased padding
        width=12,  # Set fixed width
        height=2,  # Set fixed height
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

    global file_entry
    file_entry = tk.Entry(file_frame, bg="#FFFFFF", fg="#000000", font=("Times New Roman", 10), width=70)
    file_entry.grid(row=1, column=0, padx=5, pady=5)

    # Password entry section
    password_frame = tk.Frame(card_frame, bg="#FFFFFF")
    password_frame.pack(pady=10)

    password_label = tk.Label(password_frame, text="Enter Password [12+ characters]", bg="#FFFFFF", fg="#757575", font=("Times New Roman", 12))
    password_label.grid(row=0, column=0, padx=5, pady=(0, 5))

    global password_entry
    password_entry = tk.Entry(password_frame, show='*', bg="#FFFFFF", fg="#000000", font=("Times New Roman", 10), width=40)
    password_entry.grid(row=1, column=0, padx=5)

    # Save button
    button_frame = tk.Frame(card_frame, bg="#FFFFFF")
    button_frame.pack(pady=20)

    save_button = tk.Button(button_frame, text="Encrypt", command=save_file, bg="#0066FF", fg="#FFFFFF", font=("Times New Roman", 14, "bold"), padx=10, pady=5, bd=0, relief="ridge")
    save_button.grid(row=0, column=1, padx=5)

    # Back button
    back_button = tk.Button(button_frame, text=" Back ", command=show_main_page, bg="#FF0000", fg="#FFFFFF", font=("Times New Roman", 14, "bold"), padx=10, pady=5, bd=0, relief="ridge")
    back_button.grid(row=0, column=0, padx=5)

    # Status label
    global status_label
    status_label = tk.Label(card_frame, text="", bg="#FFFFFF", font=("Times New Roman", 10))
    status_label.pack(pady=10)

    # Circular progress indicator canvas
    global progress_canvas
    progress_canvas = tk.Canvas(card_frame, width=100, height=100, bg="#FFFFFF", highlightthickness=0)
    progress_canvas.pack(pady=10)

    # Variable to store selected file path
    global selected_file
    selected_file = tk.StringVar()

# Function to show the decryption page
def show_decryption_page():
    for widget in app.winfo_children():
        widget.destroy()

    # Card-style frame for containing widgets
    card_frame = tk.Frame(app, bg="#FFFFFF", bd=2, relief="raised")
    card_frame.place(relx=0.5, rely=0.5, anchor="center", width=800, height=500)

    # Title
    title_label = tk.Label(card_frame, text="FileSecure Decrypter", font=("Times New Roman", 24, "bold"), bg="#FFFFFF", fg="#3E50B4")
    title_label.pack(pady=20)

    # File selection frame
    file_frame = tk.Frame(card_frame, bg="#FFFFFF")
    file_frame.pack(pady=10)

    select_file_btn = tk.Button(file_frame, text="Select File for Decryption", command=on_select_encrypted_file, bg="#0066FF", fg="#FFFFFF", font=("Times New Roman", 14, "bold"), padx=10, pady=5, bd=0, relief="groove")
    select_file_btn.grid(row=0, column=0, padx=5)

    global file_entry
    file_entry = tk.Entry(file_frame, bg="#FFFFFF", fg="#000000", font=("Times New Roman", 10), width=70)
    file_entry.grid(row=1, column=0, padx=5, pady=5)

    # Password entry section
    password_frame = tk.Frame(card_frame, bg="#FFFFFF")
    password_frame.pack(pady=10)

    password_label = tk.Label(password_frame, text="Enter Password [12+ characters]", bg="#FFFFFF", fg="#757575", font=("Times New Roman", 12))
    password_label.grid(row=0, column=0, padx=5, pady=(0, 5))

    global password_entry
    password_entry = tk.Entry(password_frame, show='*', bg="#FFFFFF", fg="#000000", font=("Times New Roman", 10), width=40)
    password_entry.grid(row=1, column=0, padx=5)

    # Decrypt button
    button_frame = tk.Frame(card_frame, bg="#FFFFFF")
    button_frame.pack(pady=20)

    # Back button
    back_button = tk.Button(button_frame, text=" Back ", command=show_main_page, bg="#FF0000", fg="#FFFFFF", font=("Times New Roman", 14, "bold"), padx=10, pady=5, bd=0, relief="ridge")
    back_button.grid(row=0, column=0, padx=5)

    decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_encrypted_file, bg="#0066FF", fg="#FFFFFF", font=("Times New Roman", 14, "bold"), padx=10, pady=5, bd=0, relief="ridge")
    decrypt_button.grid(row=0, column=1, padx=5)

    # Status label
    global status_label
    status_label = tk.Label(card_frame, text="", bg="#FFFFFF", font=("Times New Roman", 10))
    status_label.pack(pady=10)

    # Circular progress indicator canvas
    global progress_canvas
    progress_canvas = tk.Canvas(card_frame, width=100, height=100, bg="#FFFFFF", highlightthickness=0)
    progress_canvas.pack(pady=10)

    # Variable to store selected file path
    global selected_file
    selected_file = tk.StringVar()

# Main window configuration
app = tk.Tk()
app.title("FileSecure")
app.geometry("750x500")
app.configure(bg="#FFFFFF")

# Run the application
show_main_page()
app.mainloop()