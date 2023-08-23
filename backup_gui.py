import os
import sys
import threading
import smbclient
import stat
import logging
from tkinter import *
from tkinter import ttk, messagebox
from getpass import getpass
from pathlib import Path
import time

DOMAIN = "raymourflanigan.local"
SHARE_PATH = r"\\raymourflanigan.local\root\Departments\LegalRetention\Prior Associate Data retention"
FILE = "file"
DIRECTORY = "directory"
SYMLINK = "symlink"
UNKNOWN = "unknown"

class BackupGUI:
    def __init__(self, master):
        self.master = master
        master.title("Christine's Backup Tool v0.4i")

        for i in range(5):
            master.grid_rowconfigure(i, weight=0)
        master.grid_rowconfigure(5, weight=1)
        master.grid_rowconfigure(6, weight=0)
        for i in range(2):
            master.grid_columnconfigure(i, weight=1)

        self.hostname_label = Label(master, text="Hostname:")
        self.hostname_label.grid(row=0, column=0, sticky=E, pady=(0, 2))

        self.hostname_value = StringVar()
        self.hostname_entry = Entry(master, textvariable=self.hostname_value)
        self.hostname_entry.grid(row=0, column=1, sticky=W, pady=(0, 2))

        self.username_label = Label(master, text="Username:")
        self.username_label.grid(row=1, column=0, sticky=E, pady=(0, 2))

        self.username_value = StringVar()
        self.username_entry = Entry(master, textvariable=self.username_value)
        self.username_entry.grid(row=1, column=1, sticky=W, pady=(0, 2))

        self.password_label = Label(master, text="Password:")
        self.password_label.grid(row=2, column=0, sticky=E, pady=(0, 2))

        self.password_value = StringVar()
        self.password_entry = Entry(master, textvariable=self.password_value, show="*")
        self.password_entry.grid(row=2, column=1, sticky=W, pady=(0, 2))
        
        button_frame = Frame(master)
        button_frame.grid(row=3, rowspan=2, columnspan=2)

        for i in range(3):
            button_frame.grid_columnconfigure(i, weight=1)

        self.backup_button = Button(button_frame, text="Start Backup", command=self.start_backup_thread)
        self.backup_button.grid(row=0, column=0, sticky=EW, pady=(2, 2))

        self.stop_button = Button(button_frame, text="Stop Backup", command=self.stop_backup, state=DISABLED)
        self.stop_button.grid(row=0, column=1, sticky=EW, pady=(2, 2))

        self.total_files = 0
        self.file_list = Text(master, height=10, width=80, font=("Courier", 10), wrap=WORD)
        self.file_list.grid(row=5, rowspan=2, columnspan=2, sticky=NSEW)

        self.status_value = StringVar()

        self.logger = logging.getLogger('BackupToolLogger')
        self.log_info("Idle", user_friendly=True)
        
        self.progress = ttk.Progressbar(master, orient=HORIZONTAL, length=100, mode='indeterminate')
        self.progress.grid(row=6, columnspan=2, sticky=NSEW)

        self.backup_data_thread = None
        self.stop_event = threading.Event()
        
        self.skip_admin_accounts = BooleanVar()
        self.skip_admin_accounts.set(True)
        self.skip_admin_accounts_checkbox = Checkbutton(master, text="Skip Administrator Accounts", variable=self.skip_admin_accounts)
        self.skip_admin_accounts_checkbox.grid(row=0, column=1, sticky=E)

        self.skip_programdata_folder = BooleanVar()
        self.skip_programdata_folder_checkbox = Checkbutton(master, text="Skip ProgramData Folder", variable=self.skip_programdata_folder)
        self.skip_programdata_folder_checkbox.grid(row=1, column=1, sticky=E)
        
        self.copy_local_disk = BooleanVar()
        self.copy_local_disk_checkbox = Checkbutton(master, text="Copy All Local Files on C:", variable=self.copy_local_disk, command=self.on_copy_local_disk_changed)
        self.copy_local_disk_checkbox.grid(row=2, column=1, sticky=E)

        self.error_dict = {}
        master.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def on_close(self):
        if self.backup_data_thread and self.backup_data_thread.is_alive():
            self.stop_backup()
        self.master.destroy()
        
        
    def setup_logger(self, destination_folder):
        file_handler = logging.FileHandler(filename=os.path.join(destination_folder, 'backup_logs.txt'), mode='w')
        formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.setLevel(logging.INFO)
        
    def log_to_text_widget(self, message, user_friendly=True):
        if user_friendly:
            self.file_list.insert(END, message + '\n')
            self.file_list.see(END)
        self.log_info(message)
        
    def log_info(self, message, user_friendly=False):
        if user_friendly:
            self.file_list.insert(END, message + '\n')
            self.file_list.see(END)
        self.logger.info(message)
        
    def update_progressbar(self, value):
        self.progress['value'] += value
        self.master.after(100, self.update_progressbar)
        
    def start_backup_thread(self):
        self.log_info("Starting backup_data_thread", user_friendly=True)
        self.stop_event.clear()
        self.backup_data_thread = threading.Thread(target=self.backup_data)
        self.backup_data_thread.start()
        self.backup_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)

    def stop_backup(self):
        self.stop_event.set()
        self.backup_data_thread.join(timeout=1.0)
        if self.backup_data_thread.is_alive():
            self.log_info("Backup is taking longer to stop than expected.", user_friendly=True)
        else:
            self.log_info("Backup process stopped", user_friendly=True)
        self.progress.stop()
        self.backup_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
        
    def on_copy_local_disk_changed(self):
        if self.copy_local_disk.get():
            self.skip_admin_accounts.set(False)
            self.skip_programdata_folder.set(False)
            self.skip_admin_accounts_checkbox.config(state=DISABLED)
            self.skip_programdata_folder_checkbox.config(state=DISABLED)
        else:
            self.skip_admin_accounts_checkbox.config(state=NORMAL)
            self.skip_programdata_folder_checkbox.config(state=NORMAL)
            
    def backup_data(self):
        try:
            self.log_info("Entered backup_data method", user_friendly=True)
            
            hostname = self.hostname_value.get()
            username = self.username_value.get()
            password = self.password_value.get()
            
            self.log_info(f"Hostname: {hostname}", user_friendly=True)
            self.log_info(f"Username: {username}", user_friendly=True)
            self.log_info(f"Running as user: {os.getlogin()}", user_friendly=True)
            
            if self.copy_local_disk.get():
                source_folder = f"\\\\{hostname}\\C$"
                share_path = r"\\raymourflanigan.local\root\Departments\LegalRetention\Prior Associate Data retention"
                destination_folder = os.path.join(share_path, hostname)
                self.copy_directory(source_folder, destination_folder)
            else:
            
                users_path = f"\\\\{hostname}\\C$\\Users"
                
                all_users_folders = []
                for item in smbclient.scandir(users_path):
                    item_path = os.path.join(users_path, item.name)
                    item_type = self.get_file_type(item_path)
                    
                    if item_type == "file":
                        self.log_info(f"Processing file: {item_path}", user_friendly=False)
                    elif item_type == "directory":
                        self.log_info(f"Processing directory: {item_path}", user_friendly=False)
                        all_users_folders.append(item_path)
                    elif item_type == "symlink":
                        self.log_info(f"Skipping symlink: {item_path}", user_friendly=False)
                    else:
                        self.log_info(f"Skipping unknown item: {item_path}", user_friendly=False)
                        
                source_folders = [folder for folder in all_users_folders if os.path.basename(folder) != "All Users"]
                if not self.skip_programdata_folder.get():
                    source_folders.append(f"\\\\{hostname}\\C$\\ProgramData")

                self.log_info("Getting input data", user_friendly=True)
                domain = "raymourflanigan.local"
                share_path = r"\\raymourflanigan.local\root\Departments\LegalRetention\Prior Associate Data retention"
                destination_folder = os.path.join(share_path, hostname)
                items = self.smb_operation(smbclient.listdir, share_path)

                try:
                    self.log_info("Connected to the remote machine", user_friendly=True)
                except Exception as e:
                    self.log_info(f"Failed to connect to the remote machine: {e}", user_friendly=True)
                    return
                    
                self.progress.start()
                
                try:
                    items = smbclient.listdir(share_path)
                    if hostname not in items:
                        try:
                            smbclient.mkdir(destination_folder)
                        except Exception as e:
                            if 'NT_STATUS_OBJECT_NAME_COLLISION' in str(e):
                                pass
                            else:
                                raise
                        self.setup_logger(destination_folder)
                        self.log_info(f"Folder '{hostname}' created successfully.", user_friendly=True)
                except FileNotFoundError:
                    self.log_info(f"The share path '{share_path}' does not exist.", user_friendly=True)
                    return
                except Exception as e:
                    self.log_info(f"Error while trying to create destination folder: {e}", user_friendly=True)
                    return
                    
                for source_folder in source_folders:
                        if self.stop_event.is_set():
                            self.log_info("Backup process stopped in the middle of operation.", user_friendly=True)
                            return
                        try:
                            if self.get_file_type(source_folder) == "nonexistent":
                                self.log_info(f"The source folder '{source_folder}' does not exist.", user_friendly=True)
                                continue
                                
                            folder_name = os.path.basename(source_folder)
                            if self.skip_admin_accounts.get() and (folder_name.endswith("-da") or folder_name.endswith("-a") or folder_name.endswith("-A") or folder_name == "Administrator" or folder_name == "rayadmin" or folder_name == "Delete" or folder_name == "Default" or folder_name == "Default User" or folder_name == "defaultuser0" or folder_name == "Public" or folder_name == "svc_pdq"):
                                self.log_info(f"Skipping admin account: {folder_name}", user_friendly=True)
                                continue
                                
                            destination_subfolder = os.path.join(destination_folder, folder_name)
                            try:
                                smbclient.mkdir(destination_subfolder)
                            except Exception as e:
                                if "NT_STATUS_OBJECT_NAME_COLLISION" in str(e):
                                    pass
                                else:
                                    raise e
                                    
                            self.log_info(f"Copying directory from {source_folder} to {destination_subfolder}", user_friendly=True)
                            self.copy_directory(source_folder, destination_subfolder)
                        except Exception as e:
                            self.log_info(f"Error: {e}", user_friendly=True)

                self.log_info("Backup completed with following errors:", user_friendly=True)
                for error, count in self.error_dict.items():
                    self.log_info(f"Error: {error} | Occurrences: {count}", user_friendly=True)
                self.progress.stop()
                self.backup_button.config(state=NORMAL)
                self.stop_button.config(state=DISABLED)
                    
        except Exception as e:
            error_type, error_instance, traceback = sys.exc_info()
            filename = traceback.tb_frame.f_code.co_filename
            line_number = traceback.tb_lineno
            self.log_info(f"Error at {filename}, line {line_number}: {e}", user_friendly=True)
            self.progress.stop()
            self.backup_button.config(state=NORMAL)
            self.stop_button.config(state=DISABLED)
                
    def smb_operation(self, func, *args, **kwargs):
        max_retries = 5
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_message = str(e)
                if "Request requires 1 credits but only 0 credits are available" in error_message:
                    if attempt < max_retries - 1:
                        time.sleep(10 * (attempt + 1))
                        continue
                if error_message not in self.error_dict:
                    self.error_dict[error_message] = 0
                self.error_dict[error_message] += 1
                break
            
    def get_file_type(self, path):
        mode = self.smb_operation(smbclient.lstat, path).st_mode
        if mode is None:
            return "nonexistent"
        elif stat.S_ISLNK(mode):
            return "symlink"
        elif stat.S_ISDIR(mode):
            return "directory"
        elif stat.S_ISREG(mode):
            return "file"
        else:
            return "unknown"
            
    def copy_directory(self, source, destination):
        self.total_files = sum(1 for _ in smbclient.walk(source))
        self.progress['maximum'] = self.total_files
        self.progress['value'] = 0
        self.log_info(f"Total files to be copied from {source}: {self.total_files}", user_friendly=True)

        if self.stop_event.is_set():
            return
            
        for item in smbclient.listdir(source):
            print(f"Processing item: {item}")
            item_name = os.path.basename(item)
            if self.skip_admin_accounts.get() and (item_name.endswith("-da") or item_name.endswith("-a") or item_name == "Administrator" or item_name == "rayadmin" or item_name == "Delete" or item_name == "Default" or item_name == "Default User" or item_name == "defaultuser0" or item_name == "Public" or item_name == "svc_pdq"):
                print(f"Skipping admin account: {item_name}")
                continue

            if self.stop_event.is_set():
                return

            source_item = os.path.join(source, item)
            destination_item = os.path.join(destination, item)
            item_type = self.get_file_type(source_item)

            if item_type in ["file", "directory"]:
                self.copy_item(source_item, destination_item, item_type)
            else:
                self.log_info(f"Skipping {item_type}: {source_item}", user_friendly=True)
                
    def smb_exists(path):
        try:
            smbclient.scandir(path)
            return True
        except FileNotFoundError:
            return False
            
    def copy_item(self, source, destination, item_type):
            try:
                if item_type == "file":
                    with smbclient.open_file(source, mode='rb') as src_file:
                        with smbclient.open_file(destination, mode='wb') as dest_file:
                            while True:
                                data = src_file.read(1024)
                                if not data:
                                    break
                                dest_file.write(data)
                    self.log_info(f"Copied: {source}", user_friendly=False)
                    self.progress['value'] += 1
                elif item_type == "directory":
                    smbclient.mkdir(destination)
                    self.copy_directory(source, destination)
            except Exception as e:
                self.log_info(f"Failed to copy {item_type}: {source} due to error: {str(e)}", user_friendly=True)
                self.error_dict[str(e)] = self.error_dict.get(str(e), 0) + 1
                
def main():
    root = Tk()
    backup_gui = BackupGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()