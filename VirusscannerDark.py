import os
import re
import hashlib
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import time

class DarkModeStyle:
    """Dark mode color scheme and styling"""
    BG_COLOR = "#1e1e1e"
    FRAME_BG = "#252526"
    TEXT_COLOR = "#e0e0e0"
    ACCENT_COLOR = "#007acc"
    ACCENT_HOVER = "#0098ff"
    DANGER_COLOR = "#d32f2f"
    DANGER_HOVER = "#ef5350"
    SUCCESS_COLOR = "#388e3c"
    SUCCESS_HOVER = "#4caf50"
    BORDER_COLOR = "#3f3f3f"
    
    @staticmethod
    def apply_to_window(root):
        """Apply dark theme to entire window"""
        root.configure(bg=DarkModeStyle.BG_COLOR)
    
    @staticmethod
    def configure_ttk_styles():
        """Configure ttk styles for dark mode"""
        style = ttk.Style()
        
        style.configure("TFrame", background=DarkModeStyle.BG_COLOR)
        
        style.configure("TLabelframe", background=DarkModeStyle.BG_COLOR, 
                       foreground=DarkModeStyle.TEXT_COLOR,
                       bordercolor=DarkModeStyle.BORDER_COLOR)
        style.configure("TLabelframe.Label", background=DarkModeStyle.BG_COLOR,
                      foreground=DarkModeStyle.TEXT_COLOR)
        
        style.configure("TLabel", background=DarkModeStyle.BG_COLOR,
                      foreground=DarkModeStyle.TEXT_COLOR)
        
        style.configure("TButton", background=DarkModeStyle.FRAME_BG,
                      foreground=DarkModeStyle.TEXT_COLOR,
                      bordercolor=DarkModeStyle.BORDER_COLOR)
        style.map("TButton", 
                background=[('active', DarkModeStyle.FRAME_BG)],
                foreground=[('active', DarkModeStyle.TEXT_COLOR)])
        
        style.configure("Accent.TButton", background=DarkModeStyle.ACCENT_COLOR,
                      foreground="white")
        style.map("Accent.TButton", 
                background=[('active', DarkModeStyle.ACCENT_HOVER)],
                foreground=[('active', 'white')])
        
        style.configure("Danger.TButton", background=DarkModeStyle.DANGER_COLOR,
                      foreground="white")
        style.map("Danger.TButton", 
                background=[('active', DarkModeStyle.DANGER_HOVER)],
                foreground=[('active', 'white')])
        
        style.configure("Success.TButton", background=DarkModeStyle.SUCCESS_COLOR,
                      foreground="white")
        style.map("Success.TButton", 
                background=[('active', DarkModeStyle.SUCCESS_HOVER)],
                foreground=[('active', 'white')])
        
        style.configure("TEntry", 
                      fieldbackground=DarkModeStyle.FRAME_BG,
                      foreground=DarkModeStyle.TEXT_COLOR,
                      insertcolor=DarkModeStyle.TEXT_COLOR)
        
        style.configure("TProgressbar", 
                      background=DarkModeStyle.ACCENT_COLOR,
                      troughcolor=DarkModeStyle.FRAME_BG,
                      bordercolor=DarkModeStyle.BORDER_COLOR)
        
        style.configure("Treeview", 
                      background=DarkModeStyle.FRAME_BG,
                      foreground=DarkModeStyle.TEXT_COLOR,
                      fieldbackground=DarkModeStyle.FRAME_BG)
        style.configure("Treeview.Heading", 
                      background=DarkModeStyle.BG_COLOR,
                      foreground=DarkModeStyle.TEXT_COLOR,
                      relief="flat")
        style.map("Treeview", 
                background=[('selected', DarkModeStyle.ACCENT_COLOR)],
                foreground=[('selected', 'white')])
        style.map("Treeview.Heading",
                background=[('active', DarkModeStyle.ACCENT_COLOR)],
                foreground=[('active', 'white')])

class MalwareScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Malware Scanner - Dark Mode")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        DarkModeStyle.apply_to_window(root)
        DarkModeStyle.configure_ttk_styles()
        
        self.suspicious_files = []
        self.scan_directory = tk.StringVar()
        self.scan_status = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0)
        self.files_scanned = tk.IntVar(value=0)
        self.files_flagged = tk.IntVar(value=0)
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self._create_scan_frame()
        self._create_results_frame()
        self._create_status_bar()

    def _create_scan_frame(self):
        scan_frame = ttk.LabelFrame(self.main_frame, text="Scan Configuration", padding="10")
        scan_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(scan_frame, text="Directory to scan:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        dir_frame = ttk.Frame(scan_frame)
        dir_frame.grid(row=0, column=1, sticky=tk.EW, padx=5)
        
        dir_entry = ttk.Entry(dir_frame, textvariable=self.scan_directory, width=50)
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_btn = ttk.Button(dir_frame, text="Browse", command=self._browse_directory)
        browse_btn.pack(side=tk.RIGHT, padx=5)
        
        btn_frame = ttk.Frame(scan_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self._start_scan, style="Accent.TButton")
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        scan_frame.columnconfigure(1, weight=1)
        
    def _create_results_frame(self):
        results_frame = ttk.LabelFrame(self.main_frame, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        columns = ("path", "reason", "is_executable", "hash")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        self.results_tree.heading("path", text="File Path")
        self.results_tree.heading("reason", text="Detection Reason")
        self.results_tree.heading("is_executable", text="Executable")
        self.results_tree.heading("hash", text="SHA-256 Hash")
        
        self.results_tree.column("path", width=300)
        self.results_tree.column("reason", width=200)
        self.results_tree.column("is_executable", width=80)
        self.results_tree.column("hash", width=150)
        
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky=tk.NSEW)
        v_scrollbar.grid(row=0, column=1, sticky=tk.NS)
        h_scrollbar.grid(row=1, column=0, sticky=tk.EW)
        
        action_frame = ttk.Frame(results_frame, padding="5")
        action_frame.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=10)
        
        self.quarantine_btn = ttk.Button(action_frame, text="Quarantine Selected", 
                                     command=lambda: self._handle_files("quarantine"), state=tk.DISABLED)
        self.quarantine_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_btn = ttk.Button(action_frame, text="Delete Selected", 
                                 command=lambda: self._handle_files("delete"), 
                                 style="Danger.TButton", state=tk.DISABLED)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        
        self.quarantine_all_btn = ttk.Button(action_frame, text="Quarantine All", 
                                         command=lambda: self._handle_files("quarantine_all"), 
                                         style="Success.TButton", state=tk.DISABLED)
        self.quarantine_all_btn.pack(side=tk.RIGHT, padx=5)
        
        self.delete_all_btn = ttk.Button(action_frame, text="Delete All", 
                                     command=lambda: self._handle_files("delete_all"), 
                                     style="Danger.TButton", state=tk.DISABLED)
        self.delete_all_btn.pack(side=tk.RIGHT, padx=5)
        
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
    def _create_status_bar(self):
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
        
        self.progress_bar = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, 
                                           variable=self.progress_var, length=100, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, padx=10, fill=tk.X, expand=True)
        
        status_label = ttk.Label(status_frame, textvariable=self.scan_status, anchor=tk.W)
        status_label.pack(side=tk.LEFT, fill=tk.X, padx=10)
        
        counter_frame = ttk.Frame(self.main_frame)
        counter_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
        
        ttk.Label(counter_frame, text="Files Scanned:").pack(side=tk.LEFT, padx=10)
        ttk.Label(counter_frame, textvariable=self.files_scanned).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(counter_frame, text="Suspicious Files:").pack(side=tk.LEFT, padx=10)
        ttk.Label(counter_frame, textvariable=self.files_flagged).pack(side=tk.LEFT, padx=5)
        
    def _browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.scan_directory.set(directory)
    
    def _start_scan(self):
        directory = self.scan_directory.get()
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Error", "Please select a valid directory to scan")
            return
        
        self.results_tree.delete(*self.results_tree.get_children())
        self.suspicious_files = []
        self.files_scanned.set(0)
        self.files_flagged.set(0)
        
        self._set_button_states(tk.DISABLED)
        
        self.scan_status.set("Scanning...")
        self.progress_var.set(0)
        scan_thread = threading.Thread(target=self._scan_directory_thread, args=(directory,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def _scan_directory_thread(self, directory_path):
        try:
            total_files = sum([len(files) for _, _, files in os.walk(directory_path)])
            scanned = 0
            
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        if os.path.islink(file_path) or os.path.getsize(file_path) > 100 * 1024 * 1024:
                            continue
                        
                        is_exec = self._is_executable(file_path)
                        suspicious, reason = self._check_suspicious_patterns(file_path)
                        
                        if suspicious:
                            file_info = {
                                'path': file_path,
                                'reason': reason,
                                'is_executable': "Yes" if is_exec else "No",
                                'hash': self._calculate_file_hash(file_path)
                            }
                            self.suspicious_files.append(file_info)
                            
                            self.root.after(0, lambda f=file_info: self._add_result_to_tree(f))
                            self.root.after(0, lambda: self.files_flagged.set(len(self.suspicious_files)))
                    except Exception as e:
                        self.root.after(0, lambda p=file_path, err=str(e): 
                                       self.scan_status.set(f"Error processing {p}: {err}"))
                    
                    scanned += 1
                    progress = (scanned / total_files) * 100 if total_files > 0 else 0
                    
                    self.root.after(0, lambda v=progress: self.progress_var.set(v))
                    self.root.after(0, lambda v=scanned: self.files_scanned.set(v))
            
            self.root.after(0, self._scan_completed)
            
        except Exception as e:
            self.root.after(0, lambda: self.scan_status.set(f"Scan error: {str(e)}"))
    
    def _scan_completed(self):
        self.scan_status.set(f"Scan completed. Found {len(self.suspicious_files)} suspicious files.")
        self.progress_var.set(100)
        
        if self.suspicious_files:
            self._set_button_states(tk.NORMAL)
        else:
            messagebox.showinfo("Scan Complete", "No suspicious files were found.")
    
    def _add_result_to_tree(self, file_info):
        self.results_tree.insert("", "end", values=(
            file_info['path'], 
            file_info['reason'],
            file_info['is_executable'],
            file_info['hash']
        ))
    
    def _set_button_states(self, state):
        self.quarantine_btn.config(state=state)
        self.delete_btn.config(state=state)
        self.quarantine_all_btn.config(state=state)
        self.delete_all_btn.config(state=state)
    
    def _handle_files(self, action):
        if action == "quarantine_all" or action == "delete_all":
            files_to_handle = self.suspicious_files
        else:
            selected_items = self.results_tree.selection()
            if not selected_items:
                messagebox.showinfo("Selection", "Please select files first")
                return
            
            files_to_handle = []
            for item in selected_items:
                path = self.results_tree.item(item, "values")[0]
                for file_info in self.suspicious_files:
                    if file_info['path'] == path:
                        files_to_handle.append(file_info)
                        break
        
        if action.startswith("quarantine"):
            self._quarantine_files(files_to_handle)
        else:  
            self._delete_files(files_to_handle)
    
    def _quarantine_files(self, files):
        quarantine_dir = self._create_quarantine_dir()
        
        success_count = 0
        for file_info in files:
            try:
                file_path = file_info['path']
                dest = os.path.join(quarantine_dir, os.path.basename(file_path))
                shutil.move(file_path, dest)
                success_count += 1
                
                for item in self.results_tree.get_children():
                    if self.results_tree.item(item, "values")[0] == file_path:
                        self.results_tree.delete(item)
                        break
                
                self.suspicious_files = [f for f in self.suspicious_files if f['path'] != file_path]
                
            except Exception as e:
                messagebox.showerror("Error", f"Error quarantining {file_info['path']}: {e}")
        
        self.files_flagged.set(len(self.suspicious_files))
        
        if success_count > 0:
            messagebox.showinfo("Quarantine Complete", 
                               f"Successfully quarantined {success_count} files to:\n{quarantine_dir}")
            
        if not self.suspicious_files:
            self._set_button_states(tk.DISABLED)
    
    def _delete_files(self, files):
        if not messagebox.askyesno("Confirm Deletion", 
                                 "Are you sure you want to permanently delete these files?"):
            return
        
        success_count = 0
        for file_info in files:
            try:
                file_path = file_info['path']
                os.remove(file_path)
                success_count += 1
                
                for item in self.results_tree.get_children():
                    if self.results_tree.item(item, "values")[0] == file_path:
                        self.results_tree.delete(item)
                        break
                
                self.suspicious_files = [f for f in self.suspicious_files if f['path'] != file_path]
                
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting {file_info['path']}: {e}")
        
        self.files_flagged.set(len(self.suspicious_files))
        
        if success_count > 0:
            messagebox.showinfo("Deletion Complete", f"Successfully deleted {success_count} files.")
            
        if not self.suspicious_files:
            self._set_button_states(tk.DISABLED)
    
    def _calculate_file_hash(self, file_path):
        """Calculate the SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _check_suspicious_patterns(self, file_path):
        """Check file for suspicious patterns."""
        suspicious_patterns = [
            rb'CreateRemoteThread',
            rb'VirtualAllocEx',
            rb'ShellExecute',
            rb'GetProcAddress',
            rb'WriteProcessMemory',
            rb'ws2_32.dll',
            rb'CreateProcess',
            rb'powershell -e',
            rb'cmd.exe /c',
            rb'base64 -d',
            rb'eval\(.*\)',
            rb'exec\(',
            rb'system\(',
            rb'\.locked$',
            rb'\.encrypt$',
            rb'\.crypted$',
            rb'\.crypt$',
            rb'\.CRYPTED$',
            rb'\.CRYPT$',
            rb'\.LOCKED$',
        ]
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  
                return False, "File too large to scan"
            
            with open(file_path, 'rb') as f:
                content = f.read()
                
            for pattern in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True, f"Found: {pattern.decode('utf-8', errors='ignore')}"
            
            return False, "No suspicious patterns found"
        except Exception as e:
            return False, f"Error scanning file: {str(e)}"

    def _is_executable(self, file_path):
        """Check if file is an executable based on extension."""
        executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.py', '.sh']
        _, ext = os.path.splitext(file_path)
        return ext.lower() in executable_extensions

    def _create_quarantine_dir(self):
        """Create a quarantine directory."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_dir = os.path.join(os.path.expanduser("~"), f"malware_quarantine_{timestamp}")
        os.makedirs(quarantine_dir, exist_ok=True)
        return quarantine_dir

def main():
    root = tk.Tk()
    app = MalwareScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()