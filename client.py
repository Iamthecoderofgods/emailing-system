# client_app.py
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import random
import json
import select
from datetime import datetime

class ClientApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.root.geometry("900x700")
        
        # Network variables
        self.client_socket = None
        self.is_connected = False
        self.server_ip = ""
        self.server_port = 8888
        self.join_code = ""
        
        # User data
        self.username = f"User{random.randint(100, 999)}"
        self.message_history = []
        self.users_list = []
        
        # Thread control
        self.running = True
        self.typing_users = set()
        
        # Setup UI
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_ui(self):
        # Configure main window
        self.root.configure(bg="#1e1e1e")
        
        # Title
        title_label = tk.Label(
            self.root, 
            text="Chat Client", 
            font=("Segoe UI", 24, "bold"),
            bg="#1e1e1e",
            fg="#ffffff"
        )
        title_label.pack(pady=20)
        
        # Connection frame
        conn_frame = tk.Frame(self.root, bg="#252526")
        conn_frame.pack(pady=10, padx=20, fill=tk.X)
        
        # Username
        tk.Label(
            conn_frame, 
            text="Username:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).grid(row=0, column=0, sticky=tk.W, padx=(10, 5), pady=5)
        
        self.username_entry = tk.Entry(
            conn_frame, 
            font=("Segoe UI", 11),
            bg="#3c3c3c",
            fg="white",
            width=20
        )
        self.username_entry.insert(0, self.username)
        self.username_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Server IP
        tk.Label(
            conn_frame, 
            text="Server IP:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).grid(row=0, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        
        self.server_ip_entry = tk.Entry(
            conn_frame, 
            font=("Segoe UI", 11),
            bg="#3c3c3c",
            fg="white",
            width=15
        )
        self.server_ip_entry.insert(0, "127.0.0.1")
        self.server_ip_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Port
        tk.Label(
            conn_frame, 
            text="Port:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).grid(row=0, column=4, sticky=tk.W, padx=(20, 5), pady=5)
        
        self.port_entry = tk.Entry(
            conn_frame, 
            font=("Segoe UI", 11),
            bg="#3c3c3c",
            fg="white",
            width=8
        )
        self.port_entry.insert(0, "8888")
        self.port_entry.grid(row=0, column=5, sticky=tk.W, padx=5, pady=5)
        
        # Join code
        tk.Label(
            conn_frame, 
            text="Join Code:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).grid(row=1, column=0, sticky=tk.W, padx=(10, 5), pady=5)
        
        self.code_entry = tk.Entry(
            conn_frame, 
            font=("Segoe UI", 12, "bold"),
            bg="#3c3c3c",
            fg="#3794ff",
            width=10,
            justify=tk.CENTER
        )
        self.code_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Connection buttons
        button_frame = tk.Frame(conn_frame, bg="#252526")
        button_frame.grid(row=1, column=2, columnspan=4, padx=20, pady=5)
        
        self.connect_btn = tk.Button(
            button_frame,
            text="CONNECT",
            command=self.connect_to_server,
            bg="#388a34",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=12,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = tk.Button(
            button_frame,
            text="DISCONNECT",
            command=self.disconnect,
            bg="#ca5119",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=12,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # Status frame
        status_frame = tk.Frame(self.root, bg="#1e1e1e")
        status_frame.pack(pady=10)
        
        self.status_label = tk.Label(
            status_frame, 
            text="● Not Connected", 
            bg="#1e1e1e",
            fg="#f14c4c",
            font=("Segoe UI", 11, "bold")
        )
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.users_label = tk.Label(
            status_frame, 
            text="Users: 0", 
            bg="#1e1e1e",
            fg="#cccccc",
            font=("Segoe UI", 11)
        )
        self.users_label.pack(side=tk.LEFT, padx=5)
        
        # Typing indicator
        self.typing_label = tk.Label(
            status_frame, 
            text="", 
            bg="#1e1e1e",
            fg="#dcdcaa",
            font=("Segoe UI", 10, "italic")
        )
        self.typing_label.pack(side=tk.LEFT, padx=20)
        
        # Main content area
        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel - Users list
        users_frame = tk.Frame(main_frame, bg="#252526")
        users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        tk.Label(
            users_frame, 
            text="ONLINE USERS", 
            font=("Segoe UI", 12, "bold"),
            bg="#252526",
            fg="#cccccc"
        ).pack(pady=15)
        
        # Users listbox with scrollbar
        listbox_frame = tk.Frame(users_frame, bg="#252526")
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.users_listbox = tk.Listbox(
            listbox_frame,
            bg="#3c3c3c",
            fg="white",
            font=("Segoe UI", 11),
            width=20,
            yscrollcommand=scrollbar.set,
            relief=tk.FLAT,
            selectbackground="#0e639c"
        )
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.users_listbox.yview)
        
        # Right panel - Chat area
        chat_frame = tk.Frame(main_frame, bg="#1e1e1e")
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Chat display area
        chat_display_frame = tk.Frame(chat_frame, bg="#1e1e1e")
        chat_display_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar for chat
        chat_scrollbar = tk.Scrollbar(chat_display_frame)
        chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.chat_display = tk.Text(
            chat_display_frame, 
            bg="#1e1e1e", 
            fg="white",
            font=("Segoe UI", 11),
            state=tk.DISABLED,
            yscrollcommand=chat_scrollbar.set,
            wrap=tk.WORD,
            padx=15,
            pady=15,
            relief=tk.FLAT
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        chat_scrollbar.config(command=self.chat_display.yview)
        
        # Configure tags for different message types
        self.chat_display.tag_config("system", foreground="#cccccc", font=("Segoe UI", 10, "italic"))
        self.chat_display.tag_config("self", foreground="#4ec9b0", font=("Segoe UI", 11, "bold"))
        self.chat_display.tag_config("other", foreground="#dcdcaa")
        self.chat_display.tag_config("typing", foreground="#888888", font=("Segoe UI", 10, "italic"))
        self.chat_display.tag_config("error", foreground="#f14c4c")
        
        # Message input area
        input_frame = tk.Frame(chat_frame, bg="#252526", height=100)
        input_frame.pack(fill=tk.X, pady=(10, 0))
        input_frame.pack_propagate(False)
        
        # Message entry
        self.message_entry = tk.Text(
            input_frame, 
            height=3, 
            font=("Segoe UI", 11),
            bg="#3c3c3c",
            fg="white",
            wrap=tk.WORD,
            relief=tk.FLAT,
            state=tk.DISABLED
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 5), pady=10)
        self.message_entry.bind("<Return>", self.send_message_enter)
        self.message_entry.bind("<KeyRelease>", self.on_typing)
        
        # Send button
        self.send_btn = tk.Button(
            input_frame,
            text="SEND",
            command=self.send_message,
            bg="#0e639c",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=10,
            state=tk.DISABLED,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.send_btn.pack(side=tk.RIGHT, padx=(5, 10), pady=10, fill=tk.Y)
    
    def update_typing_indicator(self):
        """Update the typing indicator"""
        if self.typing_users:
            users = list(self.typing_users)[:3]  # Show max 3 users
            if len(users) == 1:
                text = f"{users[0]} is typing..."
            elif len(users) == 2:
                text = f"{users[0]} and {users[1]} are typing..."
            else:
                text = f"{', '.join(users)} are typing..."
            self.typing_label.config(text=text)
        else:
            self.typing_label.config(text="")
    
    def on_typing(self, event=None):
        """Handle typing indicator"""
        if self.is_connected:
            # Send typing indicator
            try:
                typing_msg = json.dumps({
                    'type': 'typing',
                    'username': self.username
                })
                if self.client_socket:
                    self.client_socket.send(typing_msg.encode())
            except:
                pass
            
            # Update send button state
            message = self.message_entry.get("1.0", tk.END).strip()
            if message and self.is_connected:
                self.send_btn.config(state=tk.NORMAL, bg="#0e639c")
            else:
                self.send_btn.config(state=tk.DISABLED, bg="#555555")
    
    def connect_to_server(self):
        """Connect to the chat server"""
        server_ip = self.server_ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        code = self.code_entry.get().strip().upper()
        username = self.username_entry.get().strip()
        
        if not server_ip:
            messagebox.showwarning("Input Error", "Please enter server IP address")
            return
        
        if not port_str:
            messagebox.showwarning("Input Error", "Please enter port number")
            return
        
        if not username:
            messagebox.showwarning("Input Error", "Please enter username")
            return
        
        try:
            port = int(port_str)
            if port < 1024 or port > 65535:
                messagebox.showerror("Invalid Port", "Port must be between 1024 and 65535")
                return
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number")
            return
        
        try:
            # Create client socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            
            # Connect to server
            self.client_socket.connect((server_ip, port))
            
            # Get username request
            data = self.client_socket.recv(1024).decode()
            if data == "REQUEST_USERNAME":
                self.client_socket.send(username.encode())
            
            # Check for error
            data = self.client_socket.recv(1024).decode()
            if data.startswith("ERROR:"):
                if "MAX_REACHED" in data:
                    messagebox.showerror("Connection Error", "Chat room is full. Maximum users reached.")
                else:
                    messagebox.showerror("Connection Error", data)
                self.client_socket.close()
                self.client_socket = None
                return
            
            # Connection successful
            self.is_connected = True
            self.server_ip = server_ip
            self.server_port = port
            self.join_code = code
            self.username = username
            
            # Update UI
            self.status_label.config(text="● Connected", fg="#73c991")
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.username_entry.config(state=tk.DISABLED)
            self.server_ip_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.code_entry.config(state=tk.DISABLED)
            self.message_entry.config(state=tk.NORMAL)
            self.send_btn.config(state=tk.NORMAL)
            
            # Add connection message
            self.add_message_to_chat("system", f"Connected to {server_ip}:{port}")
            
            # Start thread to receive messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            # Process the first message (welcome)
            try:
                message_data = json.loads(data)
                self.process_received_message(message_data)
            except:
                self.add_message_to_chat("system", data)
            
        except socket.timeout:
            messagebox.showerror("Connection Error", "Connection timeout. Server might be down.")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", "Connection refused. Server might not be running.")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
    
    def receive_messages(self):
        """Receive messages from server"""
        while self.running and self.client_socket and self.is_connected:
            try:
                # Check if there's data to read
                ready_to_read, _, _ = select.select([self.client_socket], [], [], 0.1)
                if not ready_to_read:
                    continue
                
                data = self.client_socket.recv(4096)
                if not data:
                    # Server disconnected
                    if self.is_connected:
                        self.root.after(0, lambda: self.add_message_to_chat("system", "Disconnected from server"))
                        self.root.after(0, self.disconnect)
                    break
                
                try:
                    message_data = json.loads(data.decode())
                    self.root.after(0, lambda: self.process_received_message(message_data))
                except json.JSONDecodeError:
                    # Handle plain text
                    message = data.decode()
                    self.root.after(0, lambda: self.add_message_to_chat("system", message))
                    
            except Exception as e:
                if self.is_connected:
                    print(f"Error receiving message: {e}")
                    break
    
    def process_received_message(self, message_data):
        """Process a received message from server"""
        message_type = message_data.get('type', 'message')
        
        if message_type == 'system':
            message = message_data.get('message', '')
            self.add_message_to_chat("system", message)
            
        elif message_type == 'message':
            username = message_data.get('username', '')
            message = message_data.get('message', '')
            timestamp = message_data.get('timestamp', '')
            
            if username != self.username:
                display_time = f"[{timestamp}] " if timestamp else ""
                self.add_message_to_chat("other", f"{display_time}{username}: {message}")
                
        elif message_type == 'user_list':
            users = message_data.get('users', [])
            self.users_list = users
            self.update_users_list()
            self.users_label.config(text=f"Users: {len(users)}")
            
        elif message_type == 'history':
            messages = message_data.get('messages', [])
            for msg in messages:
                self.add_message_to_chat("system", msg)
                
        elif message_type == 'typing':
            username = message_data.get('username', '')
            if username != self.username:
                if username not in self.typing_users:
                    self.typing_users.add(username)
                    self.update_typing_indicator()
                    # Clear typing indicator after 3 seconds
                    self.root.after(3000, lambda: self.clear_typing(username))
    
    def clear_typing(self, username):
        """Clear typing indicator for a user"""
        if username in self.typing_users:
            self.typing_users.remove(username)
            self.update_typing_indicator()
    
    def send_message(self):
        """Send a message to the server"""
        message = self.message_entry.get("1.0", tk.END).strip()
        
        if not message or not self.is_connected:
            return
        
        try:
            message_data = json.dumps({
                'type': 'message',
                'message': message
            })
            
            if self.client_socket:
                self.client_socket.send(message_data.encode())
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.add_message_to_chat("self", f"[{timestamp}] {self.username}: {message}")
                
                # Clear message entry
                self.message_entry.delete("1.0", tk.END)
                self.send_btn.config(state=tk.DISABLED, bg="#555555")
                
        except Exception as e:
            self.add_message_to_chat("error", f"Failed to send message: {str(e)}")
    
    def send_message_enter(self, event):
        """Handle Enter key for sending messages"""
        if event.state == 1:  # Shift key
            self.message_entry.insert(tk.END, "\n")
            return "break"
        else:
            self.send_message()
            return "break"
    
    def add_message_to_chat(self, msg_type, message):
        """Add a message to the chat display"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n", msg_type)
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
        
        # Add to message history
        self.message_history.append(message)
    
    def update_users_list(self):
        """Update the users list display"""
        self.users_listbox.delete(0, tk.END)
        for user in self.users_list:
            display_name = user.split('@')[0]
            self.users_listbox.insert(tk.END, display_name)
    
    def disconnect(self):
        """Disconnect from the server"""
        self.running = False
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        
        # Reset state
        self.is_connected = False
        self.typing_users.clear()
        
        # Update UI
        self.status_label.config(text="● Not Connected", fg="#f14c4c")
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.username_entry.config(state=tk.NORMAL)
        self.server_ip_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        self.code_entry.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.typing_label.config(text="")
        
        # Clear users list
        self.users_list = []
        self.update_users_list()
        self.users_label.config(text="Users: 0")
        
        # Add disconnect message
        self.add_message_to_chat("system", "Disconnected from server")
        
        # Reset running flag
        self.running = True
    
    def on_closing(self):
        """Handle window closing"""
        if self.is_connected:
            if messagebox.askyesno("Quit", "Are you sure you want to quit? This will disconnect you from the server."):
                self.disconnect()
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = ClientApp()
    app.run()
