import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, scrolledtext
from tkinter import PhotoImage
import subprocess
import webbrowser

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
        copyright_text = "v1.1 © M.Hasanov 2025"
        
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
