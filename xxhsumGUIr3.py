import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import os
import time

class XXHGuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("xxhsum GUI")
        self.root.geometry("800x600")

        self.files = []
        self.hashes = {}
        self.durations = {}
        self.num_threads = 1  # Default to 1 thread

        # GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Browse button
        self.browse_button = tk.Button(self.root, text="Browse Files", command=self.browse_files)
        self.browse_button.pack(pady=5)

        # Thread selection input
        thread_frame = tk.Frame(self.root)
        thread_frame.pack(pady=5)

        self.thread_label = tk.Label(thread_frame, text="Threads:")
        self.thread_label.pack(side=tk.LEFT, padx=5)

        self.thread_entry = tk.Entry(thread_frame, width=5)
        self.thread_entry.insert(0, "1")  # Default to 1 thread
        self.thread_entry.pack(side=tk.LEFT, padx=5)

        # Progress bar and percentage
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.pack(pady=5)

        self.progress_label = tk.Label(self.root, text="Progress: 0%")
        self.progress_label.pack(pady=5)

        # File list table
        self.table = ttk.Treeview(self.root, columns=("Select", "File", "Hash", "Duration"), show="headings", height=15)
        self.table.bind("<Double-1>", self.toggle_selection)  # Bind double-click to toggle selection
        self.table.heading("Select", text="Select")
        self.table.heading("File", text="File")
        self.table.heading("Hash", text="Hash")
        self.table.heading("Duration", text="Duration (s)")
        self.table.column("Select", width=60, anchor="center")

        self.table.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)

        # Save, Hash Selected, and Clear buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=5)

        self.hash_selected_button = tk.Button(button_frame, text="Hash Selected", command=self.hash_selected_files)
        self.hash_selected_button.pack(side=tk.LEFT, padx=5)

        self.save_button = tk.Button(button_frame, text="Save .xxh File", command=self.save_hashes)
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(button_frame, text="Clear All", command=self.clear_all)
        self.clear_button.pack(side=tk.LEFT, padx=5)

    def browse_files(self):
        file_paths = filedialog.askopenfilenames(title="Select Files")
        if file_paths:
            self.files.extend(file_paths)
            self.update_table()

    def update_table(self):
        # Clear existing entries
        for item in self.table.get_children():
            self.table.delete(item)

        # Add new files to the table
        for file in self.files:
            hash_value = self.hashes.get(file, "")
            duration = self.durations.get(file, "")
            self.table.insert("", tk.END, values=("[ ]", file, hash_value, duration))

    def hash_all_files(self):
        if not self.files:
            messagebox.showwarning("Warning", "No files selected!")
            return

        try:
            self.num_threads = int(self.thread_entry.get())
            if self.num_threads < 1:
                raise ValueError("Threads must be at least 1")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number of threads.")
            return

        self.hashes.clear()
        self.durations.clear()
        self.progress["maximum"] = len(self.files)
        self.progress["value"] = 0
        start_time = time.time()

        for index, file in enumerate(self.files):
            self.progress["value"] = index + 1
            self.progress_label.config(text=f"Progress: {int((index + 1) / len(self.files) * 100)}%")
            self.root.update_idletasks()
            duration, hash_result = self.run_xxhsum(file)
            self.hashes[file] = hash_result
            self.durations[file] = f"{duration:.2f}"

        end_time = time.time()
        elapsed_time = end_time - start_time
        self.update_table()
        messagebox.showinfo("Info", f"Hashing completed in {elapsed_time:.2f} seconds!")

    def toggle_selection(self, event):
        item = self.table.identify_row(event.y)
        if item:
            current_value = self.table.item(item, "values")[0]
            new_value = "[x]" if current_value == "[ ]" else "[ ]"
            file = self.table.item(item, "values")[1]
            self.table.item(item, values=(new_value, file, self.hashes.get(file, ""), self.durations.get(file, "")))

    def hash_selected_files(self):
        selected_files = []
        for item in self.table.get_children():
            values = self.table.item(item, "values")
            if values[0] == "[x]":
                selected_files.append(values[1])

        if not selected_files:
            messagebox.showwarning("Warning", "No files selected for hashing!")
            return

        try:
            self.num_threads = int(self.thread_entry.get())
            if self.num_threads < 1:
                raise ValueError("Threads must be at least 1")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number of threads.")
            return

        start_time = time.time()
        for file in selected_files:
            duration, hash_result = self.run_xxhsum(file)
            self.hashes[file] = hash_result
            self.durations[file] = f"{duration:.2f}"

        end_time = time.time()
        elapsed_time = end_time - start_time
        self.update_table()
        messagebox.showinfo("Info", f"Hashing completed for selected files in {elapsed_time:.2f} seconds!")

    def run_xxhsum(self, file_path):
        try:
            command = ["xxhsum.exe", file_path]
            if self.num_threads > 1:  # Use -T only when more than 1 thread is specified
                command.insert(1, f"-T{self.num_threads}")

            start_time = time.time()
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            end_time = time.time()
            duration = end_time - start_time
            return duration, result.stdout.split()[0]  # Return duration and only the hash part
        except subprocess.CalledProcessError as e:
            return 0, f"Error: {e}"

    def clear_all(self):
        self.files.clear()
        self.hashes.clear()
        self.durations.clear()
        self.update_table()
        self.progress["value"] = 0
        self.progress_label.config(text="Progress: 0%")

    def save_hashes(self):
        if not self.hashes:
            messagebox.showwarning("Warning", "No hashes to save!")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".xxh", filetypes=[("XXH Files", "*.xxh")])
        if save_path:
            try:
                with open(save_path, "w") as f:
                    for file in self.files:
                        hash_value = self.hashes.get(file, "")
                        duration = self.durations.get(file, "")
                        f.write(f"{file}  {hash_value}  {duration}s\n")
                messagebox.showinfo("Info", "Hashes saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save hashes: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = XXHGuiApp(root)
    root.mainloop()
