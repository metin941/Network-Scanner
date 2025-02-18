import tkinter as tk
from tkinter import *
from tkinter import messagebox, scrolledtext
from tkinter import filedialog
from tkinter.ttk import Progressbar
import subprocess
import webbrowser
import paramiko
import os
import logging
from scp import SCPClient
import configparser
import time
import re

class FirmwareTool:

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = 'config.ini'
        self.target_directory = "/opt/sysone/s1pdata/fwupgrade"

        # Create the main Tkinter window
        self.root = Tk()
        self.root.title("Firmware Multi Tool")
        self.root.geometry("1305x820")
        self.root.resizable(False, False)
        blank_icon = PhotoImage(width=1, height=1)

        self.init_widgets()

    def init_widgets(self):
        # Create a bordered frame for categorized buttons
        frame_ip = LabelFrame(self.root, text="Target Device", padx=10, pady=10)
        frame_ip.place(x=10, y=0, width=225, height=85)

        # Hostname (Device IP)
        hostname_label = Label(self.root, text="Device IP:")
        hostname_label.place(x=15, y=24)
        self.hostname_entry = Entry(self.root, width=20)
        self.hostname_entry.place(x=85, y=24)
        self.add_tooltip(self.hostname_entry, "Enter a specific Device IP address (e.g., 10.170.194.179)")

        # Create a bordered frame for categorized buttons
        button_frame_fw = LabelFrame(self.root, text="Firmware Uplad & Upgrade", padx=10, pady=10)
        button_frame_fw.place(x=240, y=0, width=210, height=85)

        # Create a bordered frame for categorized buttons
        button_frame_device = LabelFrame(self.root, text="Device Actions", padx=10, pady=10)
        button_frame_device.place(x=455, y=0, width=330, height=85)

        # Create a bordered frame for categorized buttons
        button_frame_key = LabelFrame(self.root, text="Device SSH Key", padx=10, pady=10)
        button_frame_key.place(x=790, y=0, width=100, height=85)

        # Upload Button
        upload_button = Button(self.root, text="Upload Firmware File", command=self.connect_and_upload)
        upload_button.place(x=250, y=20)
        self.add_tooltip(upload_button, "Upload FW file to the selected device")

        # Create Ready File Button
        ready_button = Button(self.root, text="Upgrade", command=self.create_ready_file)
        ready_button.place(x=380, y=20)
        self.add_tooltip(ready_button, "Start upgrading FW. Device will restart itself.")

        # Clear Log Button
        clear_button = Button(self.root, text="Clear Log", command=self.clear_log)
        clear_button.place(x=10, y=780)

        # Send fs-print Command Button
        send_command_button = Button(self.root, text="Device info", command=self.send_fs_print_command)
        send_command_button.place(x=465, y=20)
        self.add_tooltip(send_command_button, "Print selected device information")

        # Create Config File Button
        create_config_button = Button(self.root, text="Select key", command=self.create_or_update_config)
        create_config_button.place(x=800, y=20, width=80)
        self.add_tooltip(create_config_button, "Select the key to enter the device")

        # Set Environment Button
        set_env_button = Button(self.root, text="Set env to 'Dev'", command=self.set_development_environment)
        set_env_button.place(x=685, y=52)
        self.add_tooltip(set_env_button, "Set the target environment to development")

        factory_reset_button = Button(self.root, text="Factory reset NGA", command=self.factory_reset)
        factory_reset_button.place(x=465, y=52)
        self.add_tooltip(factory_reset_button, "Factory reset NGA device")

        factory_reset_button_rau = Button(self.root, text="Factory reset RAU", command=self.factory_reset_rau)
        factory_reset_button_rau.place(x=575, y=52)
        self.add_tooltip(factory_reset_button_rau, "Factory reset RAU device")

        journal_log_button = Button(self.root, text="Print Debug NGA", command=self.print_journalctl)
        journal_log_button.place(x=545, y=20)
        self.add_tooltip(journal_log_button, "Print last debug logs from NGA device")

        journal_log_button_rau = Button(self.root, text="Print Debug RAU", command=self.print_journalctl_rau)
        journal_log_button_rau.place(x=655, y=20)
        self.add_tooltip(journal_log_button_rau, "Print last debug logs from RAU device")

        # Progress bar for file transfer
        self.progress_bar = Progressbar(self.root, length=1280, orient=HORIZONTAL, mode='determinate')
        self.progress_bar.place(x=10, y=750)

        # Terminal Output
        self.terminal = Text(self.root, height=40, width=160, state='normal')
        self.terminal.place(x=10, y=90)

    def add_tooltip(self, widget, text):
        ToolTip(widget, text)

    def append_to_terminal(self, message):
        # Define color tag for errors
        self.terminal.tag_config("error", foreground="red")

        # Regular expression to find "error" or "failed" (case insensitive)
        pattern = re.compile(r"\b(error|failed)\b", re.IGNORECASE)

        # Start inserting text with selective highlighting
        start_index = 0  # Keeps track of position in the message
        for match in pattern.finditer(message):
            start, end = match.span()  # Get start and end index of the match

            # Insert text before the match (normal text)
            if start_index < start:
                self.terminal.insert(END, message[start_index:start])

            # Insert the matched keyword with red highlight
            self.terminal.insert(END, message[start:end], "error")

            start_index = end  # Move index forward

        # Insert any remaining text after the last match
        if start_index < len(message):
            self.terminal.insert(END, message[start_index:])

        self.terminal.insert(END, "\n")  # Add newline
        self.terminal.see(END)  # Auto-scroll to latest message

    def create_or_update_config(self):
        key_path = filedialog.askopenfilename(title="Select Private Key",
                                              filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if not key_path:
            messagebox.showerror("Error", "No key file selected!")
            return

        if not os.path.exists(self.config_file):
            with open(self.config_file, 'w') as f:
                f.write("[settings]\n")

        self.config.read(self.config_file)
        if not self.config.has_section('settings'):
            self.config.add_section('settings')

        self.config.set('settings', 'key_path', key_path)
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)

        self.append_to_terminal(f"Config file '{self.config_file}' updated with key_path: {key_path}")
        messagebox.showinfo("Config", f"Config file updated with key_path: {key_path}")

    def connect_and_upload(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        # Read key_path from the config file
        try:
            self.config.read(self.config_file)
            key_path = self.config.get('settings', 'key_path')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read key path from config: {e}")
            return

        if not key_path:
            messagebox.showerror("Error", "No key path found in config file!")
            return

        # Select a file to upload (this file will be modified to contain only the selected device type string)
        file_path = filedialog.askopenfilename(title="Select File to Upload")
        if not file_path:
            messagebox.showerror("Error", "No file selected!")
            return

        try:

            self.append_to_terminal("Connecting to device...")

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            # Initialize the progress bar
            file_size = os.path.getsize(file_path)
            self.progress_bar['value'] = 0
            self.progress_bar['maximum'] = file_size

            # Define the SCP callback to update the progress bar
            def progress(filename, size, sent):
                self.progress_bar['value'] = sent
                self.root.update_idletasks()

            # SCP file upload with progress callback
            self.append_to_terminal(f"Uploading file to {self.target_directory}....")
            target_path = os.path.join(self.target_directory, os.path.basename(file_path)).replace("\\", "/")
            with SCPClient(ssh.get_transport(), progress=progress) as scp:
                scp.put(file_path, target_path)

            self.append_to_terminal(f"File uploaded successfully to {target_path}")

            # Verify file exists on the remote system
            check_file_command = f"test -f {target_path} && echo 'File exists' || echo 'File does not exist'"
            stdin, stdout, stderr = ssh.exec_command(check_file_command)
            file_check_result = stdout.read().decode().strip()

            if file_check_result == "File exists":
                self.append_to_terminal(f"Verification successful: {target_path} exists on the remote device.")
                messagebox.showinfo("Success", f"File uploaded and verified successfully to {target_path}")
            else:
                self.append_to_terminal(f"Error: {target_path} does not exist on the remote device.")
                messagebox.showerror("Error", f"File upload verification failed!")

        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to upload file: {e}")

    def create_ready_file(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"
        target_file = "/opt/sysone/s1pdata/fwupgrade/fw_update.ready"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        try:
            self.append_to_terminal("Connecting to device...")

            # Read key_path from the config file
            try:
                self.config.read(self.config_file)
                key_path = self.config.get('settings', 'key_path')
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read key path from config: {e}")
                return

            if not key_path:
                messagebox.showerror("Error", "No key path found in config file!")
                return

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            command = f"touch {target_file}"
            self.append_to_terminal(f"Executing command: {command}")
            stdin, stdout, stderr = ssh.exec_command(command)

            output = stdout.read().decode()
            error = stderr.read().decode()

            if error:
                self.append_to_terminal(f"Error: {error}")
                raise Exception(error)

            self.append_to_terminal(f"File {target_file} created successfully!")
            messagebox.showinfo("Success", f"File {target_file} created successfully!")
        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to create file: {e}")

    def send_fs_print_command(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        # Read key_path from the config file
        try:
            self.config.read(self.config_file)
            key_path = self.config.get('settings', 'key_path')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read key path from config: {e}")
            return

        if not key_path:
            messagebox.showerror("Error", "No key path found in config file!")
            return

        try:
            self.append_to_terminal("Connecting to device...")

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            # Send the fs-print command
            command = "fs-print"
            self.append_to_terminal(f"Executing command: {command}")
            stdin, stdout, stderr = ssh.exec_command(command)

            output = stdout.read().decode()
            error = stderr.read().decode()

            if error:
                self.append_to_terminal(f"Error: {error}")
                raise Exception(error)

            self.append_to_terminal(f"Command Output: {output}")
            messagebox.showinfo("Success", f"Command executed successfully, output printed in terminal.")

        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to execute command: {e}")

    def set_development_environment(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        # Read key_path from the config file
        try:
            self.config.read(self.config_file)
            key_path = self.config.get('settings', 'key_path')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read key path from config: {e}")
            return

        if not key_path:
            messagebox.showerror("Error", "No key path found in config file!")
            return

        try:
            self.append_to_terminal("Connecting to device...")

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            # Send the fw_setenv command
            command = "fw_setenv target_env development"
            self.append_to_terminal(f"Executing command: {command}")
            stdin, stdout, stderr = ssh.exec_command(command)

            output = stdout.read().decode()
            error = stderr.read().decode()

            if error:
                self.append_to_terminal(f"Error: {error}")
                raise Exception(error)

            self.append_to_terminal(f"Command Output: {output}")
            messagebox.showinfo("Success", f"Command executed successfully, target environment set to development!")

        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to execute command: {e}")

    def clear_log(self):
        self.terminal.delete(1.0, tk.END)  # Delete all content in the Text widget
        self.append_to_terminal("Log cleared!")

    def factory_reset(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        # Read key_path from the config file
        try:
            self.config.read(self.config_file)
            key_path = self.config.get('settings', 'key_path')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read key path from config: {e}")
            return

        if not key_path:
            messagebox.showerror("Error", "No key path found in config file!")
            return

        try:
            self.append_to_terminal("Connecting to device...")

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            # First command: touch /data/.factory-reset
            command1 = "touch /data/.factory-reset"
            self.append_to_terminal(f"Executing command: {command1}")
            stdin, stdout, stderr = ssh.exec_command(command1)

            output1 = stdout.read().decode()
            error1 = stderr.read().decode()

            if error1:
                self.append_to_terminal(f"Error: {error1}")
                raise Exception(error1)

            self.append_to_terminal(f"Command Output: {output1}")

            # Wait for 1000ms
            time.sleep(1)

            # Second command: reboot
            command2 = "reboot"
            self.append_to_terminal(f"Executing command: {command2}")
            stdin, stdout, stderr = ssh.exec_command(command2)

            output2 = stdout.read().decode()
            error2 = stderr.read().decode()

            if error2:
                self.append_to_terminal(f"Error: {error2}")
                raise Exception(error2)

            self.append_to_terminal(f"Command Output: {output2}")
            messagebox.showinfo("Success", "Commands executed successfully!")

        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to execute commands: {e}")
        finally:
            ssh.close()

    def print_journalctl(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        # Read key_path from the config file
        try:
            self.config.read(self.config_file)
            key_path = self.config.get('settings', 'key_path')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read key path from config: {e}")
            return

        if not key_path:
            messagebox.showerror("Error", "No key path found in config file!")
            return

        try:
            self.append_to_terminal("Connecting to device...")

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            # Execute command
            command1 = "journalctl -b0"
            self.append_to_terminal(f"Executing command: {command1}")
            stdin, stdout, stderr = ssh.exec_command(command1)

            output1 = stdout.read().decode()
            error1 = stderr.read().decode()

            if error1:
                self.append_to_terminal(f"Error: {error1}")
                raise Exception(error1)

            # Highlight lines containing the keyword "failed" in red
            highlighted_output = ""
            for line in output1.splitlines():
                if "failed:" in line.lower():  # Case-insensitive match
                    highlighted_output += f"\033[91m{line}\033[0m\n"  # ANSI escape code for red
                else:
                    highlighted_output += f"{line}\n"

            self.append_to_terminal("Command Output:\n" + highlighted_output)

        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to execute commands: {e}")
        finally:
            ssh.close()

    def print_journalctl_rau(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        # Read key_path from the config file
        try:
            self.config.read(self.config_file)
            key_path = self.config.get('settings', 'key_path')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read key path from config: {e}")
            return

        if not key_path:
            messagebox.showerror("Error", "No key path found in config file!")
            return

        try:
            self.append_to_terminal("Connecting to device...")

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            # Execute command
            command1 = "cat /var/log/messages"
            self.append_to_terminal(f"Executing command: {command1}")
            stdin, stdout, stderr = ssh.exec_command(command1)

            output1 = stdout.read().decode()
            error1 = stderr.read().decode()

            if error1:
                self.append_to_terminal(f"Error: {error1}")
                raise Exception(error1)

            # Highlight lines containing the keyword "failed" in red
            highlighted_output = ""
            for line in output1.splitlines():
                if "failed:" in line.lower():  # Case-insensitive match
                    highlighted_output += f"\033[91m{line}\033[0m\n"  # ANSI escape code for red
                else:
                    highlighted_output += f"{line}\n"

            self.append_to_terminal("Command Output:\n" + highlighted_output)

        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to execute commands: {e}")
        finally:
            ssh.close()

    def factory_reset_rau(self):
        hostname = self.hostname_entry.get()  # Device IP entered by the user
        port = 22
        username = "root"

        if not hostname:
            messagebox.showerror("Error", "Device IP is required!")
            return

        # Read key_path from the config file
        try:
            self.config.read(self.config_file)
            key_path = self.config.get('settings', 'key_path')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read key path from config: {e}")
            return

        if not key_path:
            messagebox.showerror("Error", "No key path found in config file!")
            return

        try:
            self.append_to_terminal("Connecting to device...")

            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Auto accept unknown host keys
            ssh.load_system_host_keys()

            # Force SSH Protocol 2
            ssh.connect(hostname, port, username, key_filename=key_path, look_for_keys=False, allow_agent=False)

            # First command: touch /data/.factory-reset
            command1 = "/opt/sysone/s1exe/etc/unconfigure.sh"
            self.append_to_terminal(f"Executing command: {command1}")
            stdin, stdout, stderr = ssh.exec_command(command1)

            output1 = stdout.read().decode()
            error1 = stderr.read().decode()

            if error1:
                self.append_to_terminal(f"Error: {error1}")
                raise Exception(error1)

            self.append_to_terminal(f"Command Output: {output1}")

            # Wait for 1000ms
            time.sleep(1)

            # Second command: reboot
            command2 = "reboot"
            self.append_to_terminal(f"Executing command: {command2}")
            stdin, stdout, stderr = ssh.exec_command(command2)

            output2 = stdout.read().decode()
            error2 = stderr.read().decode()

            if error2:
                self.append_to_terminal(f"Error: {error2}")
                raise Exception(error2)

            self.append_to_terminal(f"Command Output: {output2}")
            messagebox.showinfo("Success", "Commands executed successfully!")

        except paramiko.ssh_exception.AuthenticationException:
            self.append_to_terminal("Error: Authentication failed. Check your private key or username.")
            messagebox.showerror("Error", "Authentication failed. Check your private key or username.")
        except paramiko.ssh_exception.SSHException as e:
            self.append_to_terminal(f"Error: SSH connection failed: {e}")
            messagebox.showerror("Error", f"SSH connection failed: {e}")
        except Exception as e:
            self.append_to_terminal(f"Error: {e}")
            messagebox.showerror("Error", f"Failed to execute commands: {e}")
        finally:
            ssh.close()

class ToolTip:
    def __init__(self, widget, text, x_offset=5, y_offset=5, position='right'):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.x_offset = x_offset
        self.y_offset = y_offset
        self.position = position  # 'right', 'left', 'above', 'below'
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        widget_x = self.widget.winfo_rootx()
        widget_y = self.widget.winfo_rooty()
        widget_width = self.widget.winfo_width()
        widget_height = self.widget.winfo_height()

        # Calculate the position of the tooltip based on the chosen position
        if self.position == 'right':
            x = widget_x + widget_width + self.x_offset
            y = widget_y + self.y_offset
        elif self.position == 'left':
            x = widget_x - self.x_offset - 150  # Assuming 150px width for tooltip
            y = widget_y + self.y_offset
        elif self.position == 'above':
            x = widget_x + self.x_offset
            y = widget_y - 30  # Just above the widget
        elif self.position == 'below':
            x = widget_x + self.x_offset
            y = widget_y + widget_height + self.y_offset  # Just below the widget

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=self.text, background="#FAF09B", relief="solid", borderwidth=1)
        label.pack()

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root

        # Check if nmap is installed
        self.check_nmap_installed()

        # Setup the UI components
        self.setup_ui()

        # Add a styled copyright label
        self.create_copyright_label()

        # Menu bar for additional tools (including your menu snippet)
        menu_bar = tk.Menu(self.root)
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Firmware Multi tool", command=self.open_firmware_update_tool)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        self.root.config(menu=menu_bar)

    def open_firmware_update_tool(self):
        # This will open the Firmware Tool window
        firmware_tool = FirmwareTool()
        firmware_tool.run()  # This will start the firmware tool's GUI

    def check_nmap_installed(self):
        try:
            # Try to run "nmap --version" to check if nmap is installed
            subprocess.check_output(["nmap", "--version"], stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            # If nmap is not found, show an error message and offer to open the download page
            response = messagebox.askyesno(
                "Nmap Not Found",
                "Nmap is not installed on your system. Would you like to download it?"
            )
            if response:
                # Open the Nmap download page in the default browser
                try:
                    webbrowser.open_new_tab("https://nmap.org/download.html")
                except:
                    os.startfile("https://nmap.org/download.html")
            # Show an exit message
            messagebox.showinfo("Exiting", "This application requires Nmap to run.")
            # Use os._exit() to terminate the app without affecting the browser
            os._exit(0)

    def setup_ui(self):
        # Input section for IP range
        tk.Label(self.root, text="Enter IP Range:").place(x=10, y=10)
        self.ip_entry = tk.Entry(self.root, width=50)
        self.ip_entry.place(x=150, y=10)
        ToolTip(self.ip_entry, "Enter a network IP range (e.g., 192.168.1.0).\n This will be used to perform a network discovery scan using nmap with the -sn option\n which will check for live hosts in the specified subnet.")

        tk.Label(self.root, text="/24 (default):").place(x=460, y=10)

        # Scan button for IP range
        tk.Button(self.root, text="Scan Network", command=self.scan_network, width=20).place(x=680, y=10)

        # Input section for a specific IP address
        tk.Label(self.root, text="Enter IP Address:").place(x=10, y=45)
        self.ip_address_entry = tk.Entry(self.root, width=50)
        self.ip_address_entry.place(x=150, y=45)
        ToolTip(self.ip_address_entry, "Enter a specific IP address (e.g., 192.168.1.1) to scan a single host using nmap.\n The provided IP address will be used in the nmap command to check\n for open ports and services on the specified host.")

        # Scan button for specific IP address
        tk.Button(self.root, text="Scan IP", command=self.scan_ip, width=20).place(x=680, y=45)

        # Search section
        tk.Label(self.root, text="Search in Network Scan:").place(x=10, y=80)
        self.search_entry = tk.Entry(self.root, width=50)
        self.search_entry.place(x=150, y=80)
        ToolTip(self.search_entry, "Enter a term to search within the network scan results")

        # Search button
        tk.Button(self.root, text="Search", command=self.search_output, width=20).place(x=680, y=80)

        # Find Next button
        tk.Button(self.root, text="Find Next", command=self.find_next, width=20).place(x=500, y=80)

        # Results display for network scan
        self.result_text = scrolledtext.ScrolledText(self.root, width=100, height=15)
        self.result_text.place(x=10, y=150)

        # Results display for specific IP scan
        self.ip_result_text = scrolledtext.ScrolledText(self.root, width=100, height=15)
        self.ip_result_text.place(x=10, y=420)

        # Setup the tag for highlighting
        self.result_text.tag_configure("highlight", background="yellow")

    def scan_network(self):
        ip = self.ip_entry.get()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address.")
            return

        try:
            # Run a basic nmap ping scan to detect active devices
            nmap_command = ["nmap", "-sn", ip+"/24"]
            output = subprocess.check_output(nmap_command, text=True)

            # Process and format the output
            formatted_output = self.format_output(output)

            # Display the formatted output in the text area
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, formatted_output)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run network scan: {e}")

    def scan_ip(self):
        ip_address = self.ip_address_entry.get()
        if not ip_address:
            messagebox.showerror("Error", "Please enter an IP address.")
            return

        try:
            # Run a basic nmap scan to get detailed information about the specific IP
            nmap_command = ["nmap", ip_address]
            output = subprocess.check_output(nmap_command, text=True)

            # Process and format the output
            formatted_output = self.format_output(output)

            # Display the formatted output in the text area for specific IP scan
            self.ip_result_text.delete(1.0, tk.END)
            self.ip_result_text.insert(tk.END, formatted_output)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run IP scan: {e}")

    def search_output(self):
        # Get the search term
        search_term = self.search_entry.get().strip()
        if not search_term:
            messagebox.showwarning("Input Error", "Please enter a search term.")
            return

        # Get the current scan output
        current_output = self.result_text.get(1.0, tk.END)

        # Remove any previous highlights
        self.result_text.tag_remove("highlight", 1.0, tk.END)

        # Reset the matches and start from the beginning
        self.matches = []
        start_index = 1.0  # Start from the beginning of the text area

        # Loop through the text to find all matches
        while True:
            start_index = self.result_text.search(search_term, start_index, stopindex=tk.END, nocase=True)
            if not start_index:
                break  # No more matches found

            # Find the end position of the match
            end_index = f"{start_index}+{len(search_term)}c"

            # Highlight the found term
            self.result_text.tag_add("highlight", start_index, end_index)

            # Add the match position to the list
            self.matches.append((start_index, end_index))

            # Move the start_index to the end of the current match to continue searching
            start_index = end_index

        # If no matches were found, show a message
        if not self.matches:
            messagebox.showinfo("Search Results", "No matches found.")

        # Reset the match index to the first match
        self.match_index = 0

    def find_next(self):
        # If there are no matches, do nothing
        if not self.matches:
            return

        # Get the next match index
        self.match_index = (self.match_index + 1) % len(self.matches)

        # Get the current match position
        start_index, end_index = self.matches[self.match_index]

        # Highlight and scroll to the next match
        self.result_text.tag_remove("highlight", 1.0, tk.END)  # Clear existing highlights
        self.result_text.tag_add("highlight", start_index, end_index)  # Highlight the next match
        self.result_text.see(start_index)  # Scroll to the match

    def format_output(self, output):
        # Split the output into lines and add spacing/lines between key sections
        lines = output.split("\n")
        formatted_lines = []
        for line in lines:
            if "Nmap scan report" in line:
                # Highlight device entries with a line separator
                formatted_lines.append("\n" + "="*60 + "\n" + line)
            elif "Host is up" in line or "MAC Address" in line:
                # Indent and append supporting information
                formatted_lines.append("    " + line)
            else:
                # Append other lines without modification
                formatted_lines.append(line)
        return "\n".join(formatted_lines)

    def create_copyright_label(self):
        copyright_text = "v1.4 © M.Hasanov 2025"
        
        # Function to open the GitHub page when the label is clicked
        def open_github(event):
            webbrowser.open("https://github.com/metin941/Network-Scanner")  # Replace with your GitHub URL

        # Create the label
        label = tk.Label(
            self.root, 
            text=copyright_text,
            font=("Arial", 10, "italic"),  # Font style and size
            fg="black",                    # Text color to look like a link
            bg="#F0F0F0",                 # Background color
            padx=10,                      # Horizontal padding
            pady=5,                       # Vertical padding
            anchor="w",                   # Left align the text
            cursor="hand2"                # Change the cursor to a hand to indicate it's clickable
        )
        label.place(x=680, y=665)

        # Bind the label to the open_github function on left-click
        label.bind("<Button-1>", open_github)

# Create the GUI window
root = tk.Tk()
root.title("Siemens Network Device Scanner")
root.geometry("850x690")
root.resizable(False, False)
blank_icon = PhotoImage(width=1, height=1)
root.iconphoto(True, blank_icon)

# Create the app instance
app = NetworkScannerApp(root)

# Run the GUI loop
root.mainloop()
