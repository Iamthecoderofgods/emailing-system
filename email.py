import tkinter as tk
from tkinter import ttk, messagebox, font
import socket
import threading
import random
import time
import json
from datetime import datetime
import sys
import select

class ChatSystem:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Chat System")
        self.root.geometry("1000x750")
        
        # Network variables
        self.is_host = False
        self.is_connected = False
        self.server_socket = None
        self.client_sockets = []
        self.max_clients = 5
        self.join_code = ""
        self.client_socket = None
        self.server_port = None
        self.host_ip = self.get_local_ip()
        
        # Chat data
        self.username = "User"
        self.message_history = []
        self.users_list = []
        
        # Thread control
        self.running = True
        
        # Setup UI
        self.setup_ui()
        
        # Bind closing event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def get_local_ip(self):
        """Get the local IP address of the computer"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def setup_ui(self):
        # Configure styles
        self.root.configure(bg="#1e1e1e")
        
        # Title
        title_label = tk.Label(
            self.root, 
            text="Network Chat System", 
            font=("Segoe UI", 28, "bold"),
            bg="#1e1e1e",
            fg="#ffffff"
        )
        title_label.pack(pady=20)
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#2d2d2d")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel - Connection controls
        left_frame = tk.Frame(main_frame, bg="#252526", relief=tk.FLAT)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Connection controls
        conn_label = tk.Label(
            left_frame, 
            text="CONNECTION", 
            font=("Segoe UI", 12, "bold"),
            bg="#252526",
            fg="#cccccc"
        )
        conn_label.pack(pady=15)
        
        # Username section
        username_frame = tk.Frame(left_frame, bg="#252526")
        username_frame.pack(pady=10, padx=15, fill=tk.X)
        
        tk.Label(
            username_frame, 
            text="Username:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).pack(anchor=tk.W)
        
        self.username_entry = tk.Entry(
            username_frame, 
            font=("Segoe UI", 11),
            bg="#3c3c3c",
            fg="white",
            insertbackground="white",
            relief=tk.FLAT
        )
        self.username_entry.pack(fill=tk.X, pady=(5, 0))
        self.username_entry.insert(0, f"User{random.randint(100, 999)}")
        
        # Host button
        self.host_btn = tk.Button(
            left_frame,
            text="HOST CHAT",
            command=self.host_chat_popup,
            bg="#0e639c",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            width=20,
            height=2,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.host_btn.pack(pady=15, padx=20)
        
        # OR separator
        tk.Label(
            left_frame, 
            text="──────── OR ────────", 
            bg="#252526",
            fg="#666666",
            font=("Segoe UI", 9)
        ).pack(pady=10)
        
        # Join section
        join_label = tk.Label(
            left_frame, 
            text="JOIN CHAT", 
            font=("Segoe UI", 11, "bold"),
            bg="#252526",
            fg="#cccccc"
        )
        join_label.pack(pady=(10, 5))
        
        # Code entry
        code_frame = tk.Frame(left_frame, bg="#252526")
        code_frame.pack(pady=5, padx=15, fill=tk.X)
        
        tk.Label(
            code_frame, 
            text="Join Code:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).pack(anchor=tk.W)
        
        self.code_entry = tk.Entry(
            code_frame, 
            font=("Segoe UI", 12),
            bg="#3c3c3c",
            fg="white",
            insertbackground="white",
            relief=tk.FLAT,
            justify=tk.CENTER
        )
        self.code_entry.pack(fill=tk.X, pady=(5, 0))
        
        # IP entry (for joining)
        ip_frame = tk.Frame(left_frame, bg="#252526")
        ip_frame.pack(pady=5, padx=15, fill=tk.X)
        
        tk.Label(
            ip_frame, 
            text="Host IP:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).pack(anchor=tk.W)
        
        self.ip_entry = tk.Entry(
            ip_frame, 
            font=("Segoe UI", 11),
            bg="#3c3c3c",
            fg="white",
            insertbackground="white",
            relief=tk.FLAT
        )
        self.ip_entry.pack(fill=tk.X, pady=(5, 0))
        self.ip_entry.insert(0, self.host_ip)
        
        # Join button
        self.join_btn = tk.Button(
            left_frame,
            text="JOIN",
            command=self.join_chat,
            bg="#388a34",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=15,
            height=1,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.join_btn.pack(pady=15)
        
        # Connection info panel
        info_frame = tk.Frame(left_frame, bg="#252526", relief=tk.FLAT)
        info_frame.pack(pady=20, padx=15, fill=tk.X)
        
        self.conn_status = tk.Label(
            info_frame, 
            text="● Not Connected", 
            bg="#252526",
            fg="#f14c4c",
            font=("Segoe UI", 10, "bold")
        )
        self.conn_status.pack(anchor=tk.W, pady=(0, 10))
        
        # Code display (for host)
        self.code_display_frame = tk.Frame(info_frame, bg="#252526")
        self.code_display_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.code_label = tk.Label(
            self.code_display_frame, 
            text="Code: ", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).pack(side=tk.LEFT)
        
        self.code_display = tk.Label(
            self.code_display_frame, 
            text="------", 
            bg="#252526",
            fg="#3794ff",
            font=("Segoe UI", 10, "bold"),
            cursor="hand2"
        )
        self.code_display.pack(side=tk.LEFT)
        
        self.ip_label = tk.Label(
            info_frame, 
            text=f"Your IP: {self.host_ip}", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 9)
        )
        self.ip_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.users_label = tk.Label(
            info_frame, 
            text=f"Users: 0/{self.max_clients}", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 9)
        )
        self.users_label.pack(anchor=tk.W)
        
        # Disconnect button (initially hidden)
        self.disconnect_btn = tk.Button(
            left_frame,
            text="DISCONNECT",
            command=self.disconnect,
            bg="#ca5119",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            width=15,
            state=tk.DISABLED,
            relief=tk.FLAT
        )
        self.disconnect_btn.pack(pady=(10, 20))
        
        # Right panel - Chat area
        right_frame = tk.Frame(main_frame, bg="#1e1e1e")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Users online panel
        users_frame = tk.Frame(right_frame, bg="#252526", height=40)
        users_frame.pack(fill=tk.X, pady=(0, 10))
        users_frame.pack_propagate(False)
        
        tk.Label(
            users_frame, 
            text="ONLINE USERS", 
            font=("Segoe UI", 11, "bold"),
            bg="#252526",
            fg="#cccccc"
        ).pack(side=tk.LEFT, padx=15, pady=10)
        
        self.users_listbox = tk.Listbox(
            users_frame,
            bg="#3c3c3c",
            fg="white",
            font=("Segoe UI", 10),
            height=1,
            relief=tk.FLAT,
            selectbackground="#0e639c"
        )
        self.users_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 15), pady=10)
        
        # Chat display area
        chat_frame = tk.Frame(right_frame, bg="#1e1e1e")
        chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # Chat text widget with scrollbar
        chat_container = tk.Frame(chat_frame, bg="#1e1e1e")
        chat_container.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(chat_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Chat text widget
        self.chat_display = tk.Text(
            chat_container, 
            bg="#1e1e1e", 
            fg="white",
            font=("Segoe UI", 11),
            state=tk.DISABLED,
            yscrollcommand=scrollbar.set,
            wrap=tk.WORD,
            padx=15,
            pady=15,
            relief=tk.FLAT,
            insertbackground="white"
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.chat_display.yview)
        
        # Configure tags for different message types
        self.chat_display.tag_config("system", foreground="#cccccc", font=("Segoe UI", 10, "italic"))
        self.chat_display.tag_config("self", foreground="#4ec9b0")
        self.chat_display.tag_config("other", foreground="#dcdcaa")
        self.chat_display.tag_config("error", foreground="#f14c4c")
        
        # Message input area
        input_frame = tk.Frame(right_frame, bg="#252526", height=100)
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
            insertbackground="white"
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 5), pady=10)
        self.message_entry.bind("<Return>", self.send_message_enter)
        self.message_entry.bind("<KeyRelease>", self.update_send_button_state)
        
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
    
    def generate_join_code(self):
        """Generate a random 6-character join code"""
        return ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    
    def host_chat_popup(self):
        """Popup to configure max users before hosting"""
        popup = tk.Toplevel(self.root)
        popup.title("Host Configuration")
        popup.geometry("500x350")  # Increased size for better layout
        popup.configure(bg="#252526")
        popup.resizable(False, False)
        popup.transient(self.root)
        popup.grab_set()
        
        # Center the popup
        popup.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - popup.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - popup.winfo_height()) // 2
        popup.geometry(f"+{x}+{y}")
        
        # Title
        title_label = tk.Label(
            popup, 
            text="Create Chat Room", 
            font=("Segoe UI", 18, "bold"),
            bg="#252526",
            fg="#ffffff"
        )
        title_label.pack(pady=20)
        
        # Configuration frame
        config_frame = tk.Frame(popup, bg="#252526")
        config_frame.pack(pady=10, padx=30, fill=tk.X)
        
        # Max users selection
        max_users_label = tk.Label(
            config_frame, 
            text="Maximum Number of Users:", 
            font=("Segoe UI", 11),
            bg="#252526",
            fg="#cccccc"
        )
        max_users_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        max_users_var = tk.IntVar(value=self.max_clients)
        self.max_users_spinbox = tk.Spinbox(
            config_frame, 
            from_=2, 
            to=50, 
            textvariable=max_users_var,
            font=("Segoe UI", 12),
            width=15,
            justify=tk.CENTER,
            bg="#3c3c3c",
            fg="white",
            buttonbackground="#0e639c"
        )
        self.max_users_spinbox.grid(row=0, column=1, padx=(10, 0), pady=(0, 10))
        
        # Port selection
        port_label = tk.Label(
            config_frame, 
            text="Port (1024-65535):", 
            font=("Segoe UI", 11),
            bg="#252526",
            fg="#cccccc"
        )
        port_label.grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        
        self.port_var = tk.StringVar(value="8888")
        self.port_entry = tk.Entry(
            config_frame,
            textvariable=self.port_var,
            font=("Segoe UI", 12),
            width=15,
            justify=tk.CENTER,
            bg="#3c3c3c",
            fg="white",
            relief=tk.FLAT
        )
        self.port_entry.grid(row=1, column=1, padx=(10, 0), pady=(10, 10))
        
        # Info text
        info_label = tk.Label(
            popup, 
            text=f"Your IP address: {self.host_ip}", 
            font=("Segoe UI", 10, "bold"),
            bg="#252526",
            fg="#3794ff"
        )
        info_label.pack(pady=15)
        
        # Buttons frame
        button_frame = tk.Frame(popup, bg="#252526")
        button_frame.pack(pady=20)
        
        def create_host():
            try:
                max_users = int(self.max_users_spinbox.get())
                port = int(self.port_entry.get())
                if port < 1024 or port > 65535:
                    raise ValueError("Port must be between 1024 and 65535")
                if max_users < 2:
                    raise ValueError("Maximum users must be at least 2")
                
                self.max_clients = max_users
                self.start_server(port)
                popup.destroy()
            except ValueError as e:
                messagebox.showerror("Invalid Input", str(e))
        
        # Create button - placed first
        create_btn = tk.Button(
            button_frame,
            text="CREATE CHAT",
            command=create_host,
            bg="#0e639c",
            fg="white",
            font=("Segoe UI", 12, "bold"),
            width=15,
            height=1,
            relief=tk.FLAT,
            cursor="hand2",
            padx=20
        )
        create_btn.grid(row=0, column=0, padx=10)
        
        # Cancel button
        cancel_btn = tk.Button(
            button_frame,
            text="CANCEL",
            command=popup.destroy,
            bg="#666666",
            fg="white",
            font=("Segoe UI", 12, "bold"),
            width=15,
            height=1,
            relief=tk.FLAT,
            cursor="hand2",
            padx=20
        )
        cancel_btn.grid(row=0, column=1, padx=10)
    
    def start_server(self, port):
        """Start the chat server"""
        try:
            # Update username
            self.username = self.username_entry.get().strip() or "Host"
            
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to all interfaces
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(self.max_clients)
            self.server_port = port
            
            # Generate join code
            self.join_code = self.generate_join_code()
            
            # Update UI
            self.is_host = True
            self.is_connected = True
            self.update_connection_status()
            
            # Update code display
            self.code_display.config(text=self.join_code)
            self.code_display.bind("<Button-1>", self.enlarge_code)
            
            # Update users display
            self.users_list = [self.username]
            self.update_users_list()
            self.users_label.config(text=f"Users: 1/{self.max_clients}")
            
            # Enable/disable buttons
            self.send_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.host_btn.config(state=tk.DISABLED)
            self.join_btn.config(state=tk.DISABLED)
            self.username_entry.config(state=tk.DISABLED)
            
            # Add initial message
            self.add_message_to_chat("system", f"Chat server started on port {port}")
            self.add_message_to_chat("system", f"Join code: {self.join_code}")
            self.add_message_to_chat("system", f"Maximum users: {self.max_clients}")
            
            # Start thread to accept clients
            threading.Thread(target=self.accept_clients, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start server: {str(e)}")
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
    
    def accept_clients(self):
        """Accept incoming client connections"""
        while self.running and self.server_socket:
            try:
                client_socket, client_address = self.server_socket.accept()
                
                # Check if we've reached max clients
                if len(self.client_sockets) >= self.max_clients - 1:  # -1 for host
                    self.send_to_client(client_socket, "ERROR:MAX_REACHED")
                    client_socket.close()
                    continue
                
                # Get client username
                try:
                    client_socket.send("REQUEST_USERNAME".encode())
                    username_data = client_socket.recv(1024).decode()
                    if not username_data:
                        client_socket.close()
                        continue
                    
                    client_username = username_data.strip()
                    if not client_username:
                        client_username = f"User{len(self.client_sockets)+1}"
                    
                    # Check if username already exists
                    existing_usernames = [u.split('@')[0] for u in self.users_list]
                    if client_username in existing_usernames:
                        client_username = f"{client_username}{len(self.client_sockets)+1}"
                    
                except:
                    client_username = f"User{len(self.client_sockets)+1}"
                
                # Add client to list
                client_info = {
                    'socket': client_socket,
                    'address': client_address,
                    'username': client_username,
                    'active': True
                }
                self.client_sockets.append(client_info)
                
                # Add to users list with IP
                self.users_list.append(f"{client_username}@{client_address[0]}")
                self.update_users_list()
                
                # Update users count
                self.users_label.config(text=f"Users: {len(self.client_sockets)+1}/{self.max_clients}")
                
                # Send welcome to client
                welcome_msg = json.dumps({
                    'type': 'system',
                    'message': f'Welcome to the chat! There are {len(self.client_sockets)+1} users connected.'
                })
                self.send_to_client(client_socket, welcome_msg)
                
                # Send current user list to client
                user_list_msg = json.dumps({
                    'type': 'user_list',
                    'users': self.users_list
                })
                self.send_to_client(client_socket, user_list_msg)
                
                # Send message history to client
                history_msg = json.dumps({
                    'type': 'history',
                    'messages': self.message_history[-50:]  # Last 50 messages
                })
                self.send_to_client(client_socket, history_msg)
                
                # Broadcast new user joined
                join_msg = json.dumps({
                    'type': 'system',
                    'message': f'{client_username} has joined the chat'
                })
                self.broadcast_message(join_msg, exclude_socket=client_socket)
                self.add_message_to_chat("system", f"{client_username} has joined the chat")
                
                # Start thread to handle this client
                threading.Thread(target=self.handle_client, args=(client_info,), daemon=True).start()
                
            except Exception as e:
                if self.running:
                    print(f"Error accepting client: {e}")
    
    def handle_client(self, client_info):
        """Handle messages from a client"""
        client_socket = client_info['socket']
        username = client_info['username']
        
        while self.running and client_info['active']:
            try:
                # Check if there's data to read
                ready_to_read, _, _ = select.select([client_socket], [], [], 0.1)
                if not ready_to_read:
                    continue
                
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    message_data = json.loads(data.decode())
                    message_type = message_data.get('type', 'message')
                    
                    if message_type == 'message':
                        message = message_data.get('message', '').strip()
                        if message:
                            # Broadcast message to all other clients
                            broadcast_msg = json.dumps({
                                'type': 'message',
                                'username': username,
                                'message': message,
                                'timestamp': datetime.now().strftime("%H:%M:%S")
                            })
                            self.broadcast_message(broadcast_msg, exclude_socket=client_socket)
                            
                            # Add to host's chat
                            self.add_message_to_chat("other", f"{username}: {message}")
                            
                    elif message_type == 'typing':
                        # Broadcast typing indicator
                        typing_msg = json.dumps({
                            'type': 'typing',
                            'username': username
                        })
                        self.broadcast_message(typing_msg, exclude_socket=client_socket)
                        
                except json.JSONDecodeError:
                    # Handle plain text messages (backward compatibility)
                    message = data.decode().strip()
                    if message:
                        broadcast_msg = json.dumps({
                            'type': 'message',
                            'username': username,
                            'message': message,
                            'timestamp': datetime.now().strftime("%H:%M:%S")
                        })
                        self.broadcast_message(broadcast_msg, exclude_socket=client_socket)
                        self.add_message_to_chat("other", f"{username}: {message}")
                
            except Exception as e:
                if client_info['active']:
                    print(f"Error handling client {username}: {e}")
                break
        
        # Client disconnected
        client_info['active'] = False
        self.remove_client(client_info)
    
    def remove_client(self, client_info):
        """Remove a disconnected client"""
        try:
            client_socket = client_info['socket']
            username = client_info['username']
            
            # Remove from client sockets list
            for i, client in enumerate(self.client_sockets):
                if client['socket'] == client_socket:
                    self.client_sockets.pop(i)
                    break
            
            # Remove from users list
            user_to_remove = None
            for user in self.users_list:
                if user.startswith(username + "@"):
                    user_to_remove = user
                    break
            
            if user_to_remove:
                self.users_list.remove(user_to_remove)
                self.update_users_list()
            
            # Update users count
            self.users_label.config(text=f"Users: {len(self.client_sockets)+1}/{self.max_clients}")
            
            # Broadcast user left
            leave_msg = json.dumps({
                'type': 'system',
                'message': f'{username} has left the chat'
            })
            self.broadcast_message(leave_msg)
            self.add_message_to_chat("system", f"{username} has left the chat")
            
            # Close socket
            client_socket.close()
            
        except Exception as e:
            print(f"Error removing client: {e}")
    
    def broadcast_message(self, message, exclude_socket=None):
        """Send a message to all connected clients"""
        for client in self.client_sockets:
            if client['socket'] != exclude_socket and client['active']:
                try:
                    self.send_to_client(client['socket'], message)
                except:
                    client['active'] = False
    
    def send_to_client(self, client_socket, message):
        """Send a message to a specific client"""
        try:
            client_socket.send(message.encode())
        except:
            pass
    
    def join_chat(self):
        """Join an existing chat room"""
        code = self.code_entry.get().strip().upper()
        host_ip = self.ip_entry.get().strip()
        username = self.username_entry.get().strip() or f"User{random.randint(100, 999)}"
        
        if not code:
            messagebox.showwarning("Input Error", "Please enter a join code")
            return
        
        if not host_ip:
            messagebox.showwarning("Input Error", "Please enter the host IP address")
            return
        
        # Default port is 8888
        port = 8888
        
        # Check if port is specified in IP
        if ":" in host_ip:
            parts = host_ip.split(":")
            host_ip = parts[0]
            try:
                port = int(parts[1])
            except:
                pass
        
        try:
            # Create client socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)  # 5 second timeout
            
            # Connect to server
            self.client_socket.connect((host_ip, port))
            
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
            self.is_host = False
            self.join_code = code
            self.username = username
            
            # Update UI
            self.update_connection_status()
            self.code_display.config(text=self.join_code)
            self.code_display.unbind("<Button-1>")
            self.code_label.config(text="Joined: ")
            
            # Enable/disable buttons
            self.send_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.host_btn.config(state=tk.DISABLED)
            self.join_btn.config(state=tk.DISABLED)
            self.username_entry.config(state=tk.DISABLED)
            
            # Add connection message
            self.add_message_to_chat("system", f"Connected to {host_ip}:{port}")
            
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
        """Receive messages from server (for clients)"""
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
            self.users_label.config(text=f"Users: {len(users)}/?")
            
        elif message_type == 'history':
            messages = message_data.get('messages', [])
            for msg in messages:
                self.add_message_to_chat("system", msg)
    
    def send_message(self):
        """Send a message to the chat"""
        message = self.message_entry.get("1.0", tk.END).strip()
        
        if not message:
            return
        
        # Clear the message entry
        self.message_entry.delete("1.0", tk.END)
        
        if self.is_host:
            # Host sends to all clients
            timestamp = datetime.now().strftime("%H:%M:%S")
            broadcast_msg = json.dumps({
                'type': 'message',
                'username': self.username,
                'message': message,
                'timestamp': timestamp
            })
            self.broadcast_message(broadcast_msg)
            self.add_message_to_chat("self", f"[{timestamp}] {self.username}: {message}")
            
        else:
            # Client sends to server
            try:
                message_data = json.dumps({
                    'type': 'message',
                    'message': message
                })
                if self.client_socket:
                    self.client_socket.send(message_data.encode())
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    self.add_message_to_chat("self", f"[{timestamp}] {self.username}: {message}")
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
    
    def update_send_button_state(self, event=None):
        """Update send button state based on message content"""
        message = self.message_entry.get("1.0", tk.END).strip()
        if message and self.is_connected:
            self.send_btn.config(state=tk.NORMAL, bg="#0e639c")
        else:
            self.send_btn.config(state=tk.DISABLED, bg="#555555")
    
    def add_message_to_chat(self, msg_type, message):
        """Add a message to the chat display"""
        self.chat_display.config(state=tk.NORMAL)
        
        # Add timestamp for non-system messages
        if msg_type != "system":
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "system")
        
        # Add message with appropriate tag
        self.chat_display.insert(tk.END, message + "\n", msg_type)
        
        # Scroll to bottom
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
        
        # Add to message history
        self.message_history.append(message)
    
    def update_users_list(self):
        """Update the users list display"""
        self.users_listbox.delete(0, tk.END)
        for user in self.users_list:
            display_name = user.split('@')[0]  # Show only username, not IP
            self.users_listbox.insert(tk.END, display_name)
    
    def update_connection_status(self):
        """Update the connection status display"""
        if self.is_connected:
            self.conn_status.config(text="● Connected", fg="#73c991")
        else:
            self.conn_status.config(text="● Not Connected", fg="#f14c4c")
    
    def enlarge_code(self, event=None):
        """Show the join code in a larger window"""
        enlarge_window = tk.Toplevel(self.root)
        enlarge_window.title("Join Code")
        enlarge_window.geometry("500x250")
        enlarge_window.configure(bg="#252526")
        
        # Center the window
        enlarge_window.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - enlarge_window.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - enlarge_window.winfo_height()) // 2
        enlarge_window.geometry(f"+{x}+{y}")
        
        # Title
        tk.Label(
            enlarge_window, 
            text="JOIN CODE", 
            font=("Segoe UI", 20, "bold"),
            bg="#252526",
            fg="white"
        ).pack(pady=20)
        
        # Large code display
        tk.Label(
            enlarge_window, 
            text=self.join_code, 
            font=("Courier", 42, "bold"),
            bg="#252526",
            fg="#3794ff"
        ).pack(pady=10)
        
        # Connection info
        info_text = f"Host IP: {self.host_ip}"
        if self.server_port:
            info_text += f"\nPort: {self.server_port}"
        
        tk.Label(
            enlarge_window, 
            text=info_text, 
            font=("Segoe UI", 11),
            bg="#252526",
            fg="#cccccc"
        ).pack(pady=10)
        
        # Instructions
        tk.Label(
            enlarge_window, 
            text="Share this code and IP address with others to join", 
            font=("Segoe UI", 10),
            bg="#252526",
            fg="#888888"
        ).pack(pady=10)
        
        # Close button
        tk.Button(
            enlarge_window,
            text="CLOSE",
            command=enlarge_window.destroy,
            bg="#0e639c",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            width=12,
            relief=tk.FLAT
        ).pack(pady=10)
    
    def disconnect(self):
        """Disconnect from the chat"""
        self.running = False
        
        if self.is_host:
            # Host: close all client connections and server
            for client in self.client_sockets:
                try:
                    client['socket'].close()
                except:
                    pass
            self.client_sockets.clear()
            
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
                self.server_socket = None
        else:
            # Client: close client socket
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
                self.client_socket = None
        
        # Reset state
        self.is_host = False
        self.is_connected = False
        
        # Update UI
        self.update_connection_status()
        self.code_display.config(text="------", fg="#3794ff")
        self.code_label.config(text="Code: ")
        self.code_display.unbind("<Button-1>")
        self.users_list = []
        self.update_users_list()
        self.users_label.config(text=f"Users: 0/{self.max_clients}")
        
        # Enable/disable buttons
        self.host_btn.config(state=tk.NORMAL)
        self.join_btn.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.username_entry.config(state=tk.NORMAL)
        
        # Add disconnect message
        self.add_message_to_chat("system", "Disconnected from chat")
        
        # Reset running flag for reconnection
        self.running = True
    
    def on_closing(self):
        """Handle window closing"""
        if self.is_connected:
            if messagebox.askyesno("Quit", "Are you sure you want to quit? This will disconnect you from the chat."):
                self.disconnect()
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = ChatSystem()
    app.run()