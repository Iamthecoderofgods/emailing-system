import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import socket
import threading
import json
import datetime
import sqlite3
from hashlib import sha256
import queue
import time
import sys

# ============================================
# CONFIGURATION
# ============================================

HOST_IP = '127.0.0.1'  # Change this to your IP for friends to connect
PORT = 5555

# ============================================
# CHAT APPLICATION (Combined Client & Server)
# ============================================

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Friend Chat Messenger")
        self.root.geometry("800x600")
        
        # State variables
        self.is_host = False
        self.server = None
        self.client_socket = None
        self.username = None
        self.connected = False
        self.message_queue = queue.Queue()
        
        # Colors
        self.colors = {
            'bg': '#2C3E50',
            'fg': '#ECF0F1',
            'accent': '#3498DB',
            'secondary': '#34495E',
            'success': '#2ECC71',
            'warning': '#E74C3C',
            'message_bg': '#ECF0F1',
            'message_fg': '#2C3E50'
        }
        
        self.setup_ui()
        self.startup_choice()
    
    def setup_ui(self):
        """Setup the main UI"""
        self.root.configure(bg=self.colors['bg'])
        
        # Main container
        self.main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.colors['secondary'], 
                       foreground=self.colors['fg'], padding=[10, 5])
        style.map('TNotebook.Tab', background=[('selected', self.colors['accent'])])
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Connection Tab
        self.conn_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(self.conn_tab, text='Connection')
        self.setup_connection_tab()
        
        # Chat Tab
        self.chat_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(self.chat_tab, text='Chat')
        self.setup_chat_tab()
        
        # Initially show connection tab
        self.notebook.hide(1)
    
    def startup_choice(self):
        """Ask user if they want to host or connect"""
        choice_window = tk.Toplevel(self.root)
        choice_window.title("Start Chat")
        choice_window.geometry("400x200")
        choice_window.configure(bg=self.colors['bg'])
        choice_window.transient(self.root)
        choice_window.grab_set()
        
        # Center the window
        choice_window.update_idletasks()
        x = (choice_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (choice_window.winfo_screenheight() // 2) - (200 // 2)
        choice_window.geometry(f'400x200+{x}+{y}')
        
        tk.Label(choice_window, text="Start New Chat", 
                font=("Arial", 16, "bold"),
                bg=self.colors['bg'], fg=self.colors['accent']
                ).pack(pady=20)
        
        tk.Label(choice_window, text="Choose your role:", 
                font=("Arial", 12),
                bg=self.colors['bg'], fg=self.colors['fg']
                ).pack(pady=5)
        
        button_frame = tk.Frame(choice_window, bg=self.colors['bg'])
        button_frame.pack(pady=20)
        
        # Host button (You run this first)
        host_btn = tk.Button(button_frame, text="🎮 I'M HOSTING (Start First)",
                           command=lambda: self.start_as_host(choice_window),
                           bg=self.colors['success'], fg='white',
                           font=("Arial", 11, "bold"),
                           width=25, height=2)
        host_btn.pack(pady=5)
        
        # Connect button (Your friend runs this)
        connect_btn = tk.Button(button_frame, text="🔗 JOIN FRIEND (Connect to Host)",
                               command=lambda: self.start_as_client(choice_window),
                               bg=self.colors['accent'], fg='white',
                               font=("Arial", 11, "bold"),
                               width=25, height=2)
        connect_btn.pack(pady=5)
    
    def start_as_host(self, choice_window):
        """Start as the host (server)"""
        self.is_host = True
        choice_window.destroy()
        self.start_server()
        self.show_status("You are the HOST. Tell your friend to connect to you.")
    
    def start_as_client(self, choice_window):
        """Start as client (connect to host)"""
        self.is_host = False
        choice_window.destroy()
        self.show_status("Connecting to host...")
        self.connect_to_host()
    
    def setup_connection_tab(self):
        """Setup connection tab UI"""
        # Title
        title_frame = tk.Frame(self.conn_tab, bg=self.colors['bg'])
        title_frame.pack(pady=(30, 20))
        
        title_label = tk.Label(title_frame, text="Friend Chat", 
                              font=("Helvetica", 24, "bold"), 
                              bg=self.colors['bg'], 
                              fg=self.colors['accent'])
        title_label.pack()
        
        # Status display
        self.status_frame = tk.Frame(self.conn_tab, bg=self.colors['secondary'],
                                    relief=tk.RAISED, bd=2)
        self.status_frame.pack(padx=50, pady=20, fill=tk.X)
        
        self.status_label = tk.Label(self.status_frame, text="Not connected", 
                                    bg=self.colors['secondary'], 
                                    fg=self.colors['fg'],
                                    font=("Arial", 12))
        self.status_label.pack(pady=20)
        
        # Connection info
        info_frame = tk.Frame(self.conn_tab, bg=self.colors['secondary'],
                             relief=tk.RAISED, bd=2)
        info_frame.pack(padx=50, pady=10, fill=tk.X)
        
        tk.Label(info_frame, text="Connection Information:", 
                bg=self.colors['secondary'], fg=self.colors['accent'],
                font=("Arial", 12, "bold")).pack(pady=10)
        
        self.conn_info = tk.Label(info_frame, 
                                 text=f"Host IP: {HOST_IP}\nPort: {PORT}",
                                 bg=self.colors['secondary'], fg=self.colors['fg'],
                                 font=("Arial", 10))
        self.conn_info.pack(pady=10)
        
        # Login section
        login_frame = tk.Frame(self.conn_tab, bg=self.colors['secondary'],
                              relief=tk.RAISED, bd=2)
        login_frame.pack(padx=50, pady=20, fill=tk.X)
        
        tk.Label(login_frame, text="Set Username:", 
                bg=self.colors['secondary'], fg=self.colors['fg'],
                font=("Arial", 12)).pack(pady=10)
        
        self.username_entry = tk.Entry(login_frame, font=("Arial", 12),
                                      width=30, bg='white', fg='black')
        self.username_entry.pack(pady=10)
        self.username_entry.insert(0, "YourName")
        
        self.login_btn = tk.Button(login_frame, text="Join Chat", 
                                  command=self.join_chat,
                                  bg=self.colors['accent'], fg='white',
                                  font=("Arial", 12, "bold"),
                                  width=15)
        self.login_btn.pack(pady=20)
        
        # Instructions
        inst_frame = tk.Frame(self.conn_tab, bg=self.colors['bg'])
        inst_frame.pack(padx=50, pady=10, fill=tk.X)
        
        instructions = """INSTRUCTIONS:
1. First person: Click 'I'M HOSTING'
2. Second person: Click 'JOIN FRIEND'
3. Both: Enter username and click 'Join Chat'
4. Start chatting!"""
        
        tk.Label(inst_frame, text=instructions,
                bg=self.colors['bg'], fg=self.colors['fg'],
                font=("Arial", 9), justify=tk.LEFT).pack()
    
    def setup_chat_tab(self):
        """Setup chat tab UI"""
        # Top bar
        top_frame = tk.Frame(self.chat_tab, bg=self.colors['secondary'])
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.user_label = tk.Label(top_frame, text="Not connected", 
                                  bg=self.colors['secondary'], 
                                  fg=self.colors['fg'],
                                  font=("Arial", 12))
        self.user_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.role_label = tk.Label(top_frame, text="", 
                                  bg=self.colors['secondary'], 
                                  fg=self.colors['accent'],
                                  font=("Arial", 12))
        self.role_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        # Chat display
        chat_frame = tk.Frame(self.chat_tab, bg=self.colors['bg'])
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.message_display = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD,
            bg=self.colors['message_bg'],
            fg=self.colors['message_fg'],
            font=("Arial", 11),
            state='disabled',
            height=20
        )
        self.message_display.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Message input
        input_frame = tk.Frame(self.chat_tab, bg=self.colors['secondary'])
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.message_input = tk.Text(input_frame, height=3, 
                                    bg='white', fg='black',
                                    font=("Arial", 11))
        self.message_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.send_btn = tk.Button(input_frame, text="Send", 
                                 command=self.send_message,
                                 bg=self.colors['success'], fg='white',
                                 font=("Arial", 12, "bold"),
                                 height=3, width=10)
        self.send_btn.pack(side=tk.RIGHT)
        
        # Bind Enter key
        self.message_input.bind("<Return>", lambda e: self.send_message())
        self.message_input.bind("<Shift-Return>", 
                               lambda e: self.message_input.insert(tk.INSERT, '\n'))
    
    def show_status(self, message):
        """Update status display"""
        self.status_label.config(text=message)
    
    def start_server(self):
        """Start the chat server (host only)"""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((HOST_IP, PORT))
            self.server.listen(1)  # Only allow 1 connection (your friend)
            
            # Start accepting connections in background
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
            self.show_status(f"✅ Server running on {HOST_IP}:{PORT}\nWaiting for friend to connect...")
            self.role_label.config(text="[HOST]")
            
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start server:\n{str(e)}")
    
    def accept_connections(self):
        """Accept incoming connections (host only)"""
        try:
            while True:
                client_socket, address = self.server.accept()
                self.client_socket = client_socket
                self.connected = True
                
                # Start receiving messages from friend
                threading.Thread(target=self.receive_messages, daemon=True).start()
                
                self.show_status(f"✅ Friend connected from {address}")
                self.display_message("System: Your friend has connected!", "system")
                
                # Send welcome message
                if self.username:
                    welcome = {
                        'type': 'message',
                        'sender': 'System',
                        'message': f'{self.username} is online!',
                        'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
                    }
                    self.client_socket.send(json.dumps(welcome).encode('utf-8'))
                
                break  # Only accept one connection (your friend)
                
        except Exception as e:
            print(f"Connection error: {e}")
    
    def connect_to_host(self):
        """Connect to host (client only)"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST_IP, PORT))
            self.connected = True
            
            # Start receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            self.show_status(f"✅ Connected to host at {HOST_IP}:{PORT}")
            self.role_label.config(text="[FRIEND]")
            
        except Exception as e:
            messagebox.showerror("Connection Error", 
                               f"Cannot connect to host at {HOST_IP}:{PORT}\n"
                               f"Error: {str(e)}\n\n"
                               "Make sure your friend is running as HOST first!")
    
    def join_chat(self):
        """Join the chat with username"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Username Required", "Please enter a username!")
            return
        
        self.username = username
        
        # Switch to chat tab
        self.notebook.select(1)
        self.notebook.hide(0)
        
        self.user_label.config(text=f"User: {self.username}")
        self.display_message(f"System: Welcome {self.username}!", "system")
        
        # If we're host and already connected to friend, notify them
        if self.is_host and self.connected and self.client_socket:
            join_msg = {
                'type': 'message',
                'sender': 'System',
                'message': f'{self.username} has joined the chat!',
                'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
            }
            self.client_socket.send(json.dumps(join_msg).encode('utf-8'))
    
    def send_message(self):
        """Send a message to the other person"""
        if not self.username:
            messagebox.showwarning("Not Joined", "Please join the chat first!")
            return
        
        if not self.connected:
            messagebox.showwarning("Not Connected", "Not connected to friend!")
            return
        
        message = self.message_input.get(1.0, tk.END).strip()
        if not message:
            return
        
        # Display my message
        self.display_message(f"{self.username}: {message}", "me")
        
        # Send to friend
        message_data = {
            'type': 'message',
            'sender': self.username,
            'message': message,
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
        }
        
        try:
            self.client_socket.send(json.dumps(message_data).encode('utf-8'))
        except:
            messagebox.showerror("Send Error", "Failed to send message to friend!")
        
        # Clear input
        self.message_input.delete(1.0, tk.END)
    
    def receive_messages(self):
        """Receive messages from the other person"""
        while self.connected:
            try:
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                message_data = json.loads(data)
                
                if message_data['type'] == 'message':
                    self.display_message(f"{message_data['sender']}: {message_data['message']}", "friend")
                
            except:
                break
        
        # Connection lost
        self.connected = False
        if not self.root.winfo_exists():  # Check if window still exists
            return
        
        self.display_message("System: Friend disconnected!", "system")
    
    def display_message(self, message, msg_type):
        """Display a message in the chat"""
        self.message_display.config(state='normal')
        
        # Configure tags for different message types
        if not self.message_display.tag_names():
            self.message_display.tag_config("me", foreground="#2980B9", font=("Arial", 11, "bold"))
            self.message_display.tag_config("friend", foreground="#2C3E50")
            self.message_display.tag_config("system", foreground="#E67E22", font=("Arial", 10, "italic"))
        
        # Add timestamp
        timestamp = datetime.datetime.now().strftime('%H:%M')
        
        if msg_type == "me":
            self.message_display.insert(tk.END, f"[{timestamp}] {message}\n", "me")
        elif msg_type == "friend":
            self.message_display.insert(tk.END, f"[{timestamp}] {message}\n", "friend")
        else:
            self.message_display.insert(tk.END, f"[{timestamp}] {message}\n", "system")
        
        self.message_display.config(state='disabled')
        self.message_display.see(tk.END)

# ============================================
# MAIN FUNCTION
# ============================================

def main():
    root = tk.Tk()
    app = ChatApp(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Handle window close
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit the chat?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    print("=" * 50)
    print("FRIEND CHAT MESSENGER")
    print("=" * 50)
    print("\nINSTRUCTIONS:")
    print("1. First person runs: python friend_chat.py")
    print("   -> Click 'I'M HOSTING'")
    print("2. Second person runs: python friend_chat.py")
    print("   -> Click 'JOIN FRIEND'")
    print("3. Both enter usernames and click 'Join Chat'")
    print("4. Start chatting!")
    print("=" * 50)
    print()
    
    main()

