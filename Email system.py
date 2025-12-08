import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import socket
import threading
import json
import datetime
import queue
import time

# ============================================
# CHAT APPLICATION (Simple IP Connection)
# ============================================

class SimpleChat:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Chat")
        self.root.geometry("600x500")
        
        # State variables
        self.is_host = False
        self.server = None
        self.client_socket = None
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
        
        self.root.configure(bg=self.colors['bg'])
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the main UI"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(main_frame, text="Simple Chat", 
                              font=("Arial", 20, "bold"),
                              bg=self.colors['bg'], fg=self.colors['accent'])
        title_label.pack(pady=10)
        
        # Connection Frame
        conn_frame = tk.LabelFrame(main_frame, text="Connection", 
                                  bg=self.colors['secondary'], fg=self.colors['fg'],
                                  font=("Arial", 12, "bold"))
        conn_frame.pack(fill=tk.X, pady=10, padx=5)
        
        # Your IP display
        tk.Label(conn_frame, text="Your IP:", 
                bg=self.colors['secondary'], fg=self.colors['fg'],
                font=("Arial", 10)).grid(row=0, column=0, padx=10, pady=5, sticky='w')
        
        self.your_ip_label = tk.Label(conn_frame, text=self.get_local_ip(), 
                                     bg='white', fg='black',
                                     font=("Arial", 10), relief=tk.SUNKEN, width=20)
        self.your_ip_label.grid(row=0, column=1, padx=10, pady=5, sticky='w')
        
        # Host button
        self.host_btn = tk.Button(conn_frame, text="HOST", 
                                 command=self.start_as_host,
                                 bg=self.colors['success'], fg='white',
                                 font=("Arial", 12, "bold"),
                                 width=15)
        self.host_btn.grid(row=0, column=2, padx=10, pady=5)
        
        # Separator
        separator = tk.Frame(conn_frame, height=2, bg=self.colors['bg'])
        separator.grid(row=1, column=0, columnspan=3, sticky='ew', pady=10, padx=10)
        
        # Friend IP input
        tk.Label(conn_frame, text="Friend's IP:", 
                bg=self.colors['secondary'], fg=self.colors['fg'],
                font=("Arial", 10)).grid(row=2, column=0, padx=10, pady=5, sticky='w')
        
        self.friend_ip_entry = tk.Entry(conn_frame, 
                                       font=("Arial", 10),
                                       width=20, bg='white', fg='black')
        self.friend_ip_entry.grid(row=2, column=1, padx=10, pady=5, sticky='w')
        self.friend_ip_entry.insert(0, "127.0.0.1")  # Default to localhost
        
        # Connect button
        self.connect_btn = tk.Button(conn_frame, text="CONNECT", 
                                    command=self.connect_to_friend,
                                    bg=self.colors['accent'], fg='white',
                                    font=("Arial", 12, "bold"),
                                    width=15)
        self.connect_btn.grid(row=2, column=2, padx=10, pady=5)
        
        # Status display
        self.status_label = tk.Label(main_frame, text="Not connected", 
                                    bg=self.colors['secondary'], fg=self.colors['fg'],
                                    font=("Arial", 10), relief=tk.SUNKEN,
                                    height=2, width=50)
        self.status_label.pack(pady=10)
        
        # Chat display
        chat_frame = tk.LabelFrame(main_frame, text="Chat", 
                                  bg=self.colors['secondary'], fg=self.colors['fg'],
                                  font=("Arial", 12, "bold"))
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=5)
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD,
            bg=self.colors['message_bg'],
            fg=self.colors['message_fg'],
            font=("Arial", 10),
            state='disabled',
            height=15
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message input area
        input_frame = tk.Frame(chat_frame, bg=self.colors['secondary'])
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.message_entry = tk.Entry(input_frame, 
                                     font=("Arial", 12),
                                     bg='white', fg='black')
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        self.send_btn = tk.Button(input_frame, text="Send", 
                                 command=self.send_message,
                                 bg=self.colors['accent'], fg='white',
                                 font=("Arial", 12, "bold"),
                                 width=10)
        self.send_btn.pack(side=tk.RIGHT)
    
    def get_local_ip(self):
        """Get the local IP address"""
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"  # Fallback to localhost
    
    def start_as_host(self):
        """Start as the host (server)"""
        if self.is_host:
            messagebox.showinfo("Already Hosting", "You are already hosting!")
            return
        
        self.is_host = True
        self.host_btn.config(state='disabled', bg='gray')
        self.connect_btn.config(state='disabled', bg='gray')
        
        try:
            # Start server
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind(("0.0.0.0", 5555))  # Listen on all interfaces
            self.server.listen(1)  # Only allow 1 connection
            
            # Start accepting connections in background
            threading.Thread(target=self.accept_connection, daemon=True).start()
            
            self.update_status(f"✅ Hosting on {self.get_local_ip()}:5555\nWaiting for friend to connect...")
            self.add_chat_message("System", "You are now hosting. Share your IP with friend.")
            
        except Exception as e:
            messagebox.showerror("Host Error", f"Failed to start host:\n{str(e)}")
            self.is_host = False
            self.host_btn.config(state='normal', bg=self.colors['success'])
            self.connect_btn.config(state='normal', bg=self.colors['accent'])
    
    def accept_connection(self):
        """Accept incoming connection (host only)"""
        try:
            self.client_socket, address = self.server.accept()
            self.connected = True
            
            # Start receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            self.update_status(f"✅ Friend connected from {address[0]}")
            self.add_chat_message("System", "Friend connected!")
            
            # Send welcome to friend
            welcome = {
                'type': 'message',
                'sender': 'System',
                'message': 'Host is online!',
                'time': datetime.datetime.now().strftime('%H:%M')
            }
            self.client_socket.send(json.dumps(welcome).encode('utf-8'))
            
        except Exception as e:
            print(f"Accept error: {e}")
    
    def connect_to_friend(self):
        """Connect to friend's IP"""
        friend_ip = self.friend_ip_entry.get().strip()
        if not friend_ip:
            messagebox.showwarning("IP Required", "Enter friend's IP address!")
            return
        
        if self.connected:
            messagebox.showinfo("Already Connected", "Already connected to friend!")
            return
        
        self.is_host = False
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((friend_ip, 5555))
            self.connected = True
            
            # Disable buttons
            self.host_btn.config(state='disabled', bg='gray')
            self.connect_btn.config(state='disabled', bg='gray')
            
            # Start receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            self.update_status(f"✅ Connected to {friend_ip}:5555")
            self.add_chat_message("System", f"Connected to {friend_ip}")
            
        except Exception as e:
            messagebox.showerror("Connection Failed", 
                               f"Cannot connect to {friend_ip}:5555\n"
                               f"Make sure friend is hosting first!\n\n"
                               f"Error: {str(e)}")
    
    def update_status(self, message):
        """Update status display"""
        self.status_label.config(text=message)
    
    def add_chat_message(self, sender, message):
        """Add a message to the chat display"""
        self.chat_display.config(state='normal')
        
        timestamp = datetime.datetime.now().strftime('%H:%M')
        
        if sender == "You":
            self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n", "you")
        elif sender == "System":
            self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n", "system")
        else:
            self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n", "friend")
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
    
    def send_message(self):
        """Send a message"""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Not connected to anyone!")
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        # Add to our chat
        self.add_chat_message("You", message)
        
        # Send to friend
        message_data = {
            'type': 'message',
            'sender': 'Friend',
            'message': message,
            'time': datetime.datetime.now().strftime('%H:%M')
        }
        
        try:
            self.client_socket.send(json.dumps(message_data).encode('utf-8'))
        except:
            self.add_chat_message("System", "Failed to send message!")
        
        # Clear input
        self.message_entry.delete(0, tk.END)
    
    def receive_messages(self):
        """Receive messages from friend"""
        while self.connected:
            try:
                data = self.client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                message_data = json.loads(data)
                
                if message_data['type'] == 'message':
                    if message_data['sender'] == 'System':
                        self.add_chat_message("System", message_data['message'])
                    else:
                        self.add_chat_message("Friend", message_data['message'])
                
            except Exception as e:
                print(f"Receive error: {e}")
                break
        
        # Connection lost
        self.connected = False
        
        if self.root.winfo_exists():
            self.add_chat_message("System", "Friend disconnected!")
            self.update_status("Disconnected")
            
            # Re-enable buttons
            self.host_btn.config(state='normal', bg=self.colors['success'])
            self.connect_btn.config(state='normal', bg=self.colors['accent'])

# ============================================
# MAIN FUNCTION
# ============================================

def main():
    root = tk.Tk()
    app = SimpleChat(root)
    
    # Configure chat display tags
    app.chat_display.tag_config("you", foreground="#2980B9", font=("Arial", 10, "bold"))
    app.chat_display.tag_config("friend", foreground="#2C3E50")
    app.chat_display.tag_config("system", foreground="#E67E22", font=("Arial", 9, "italic"))
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Handle window close
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    print("=" * 50)
    print("SIMPLE CHAT - IP CONNECTION")
    print("=" * 50)
    print("\nINSTRUCTIONS:")
    print("1. Person A: Click HOST button")
    print("2. Person A: Share IP address shown")
    print("3. Person B: Enter Person A's IP, click CONNECT")
    print("4. Start chatting!")
    print("\nFor same computer testing: Use 127.0.0.1")
    print("=" * 50)
    print()
    
    main()
