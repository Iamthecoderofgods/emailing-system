# host_app.py
import tkinter as tk
from tkinter import messagebox
import socket
import threading
import random
import json
import select
from datetime import datetime

class HostApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chat Host")
        self.root.geometry("800x700")
        
        # Network variables
        self.server_socket = None
        self.client_sockets = []
        self.max_clients = 10
        self.join_code = ""
        self.server_port = 8888
        
        # Chat data
        self.username = "Host"
        self.message_history = []
        self.users_list = []
        
        # Thread control
        self.running = True
        self.host_ip = self.get_local_ip()
        
        # Setup UI
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def generate_join_code(self):
        """Generate a random 6-character join code"""
        return ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    
    def setup_ui(self):
        # Configure main window
        self.root.configure(bg="#1e1e1e")
        
        # Title
        title_label = tk.Label(
            self.root, 
            text="Chat Host Server", 
            font=("Segoe UI", 24, "bold"),
            bg="#1e1e1e",
            fg="#ffffff"
        )
        title_label.pack(pady=20)
        
        # Connection info frame
        info_frame = tk.Frame(self.root, bg="#252526")
        info_frame.pack(pady=10, padx=20, fill=tk.X)
        
        # Server info
        server_info = tk.Label(
            info_frame, 
            text="SERVER INFORMATION", 
            font=("Segoe UI", 12, "bold"),
            bg="#252526",
            fg="#cccccc"
        )
        server_info.grid(row=0, column=0, columnspan=2, pady=(0, 15))
        
        # Host IP
        tk.Label(
            info_frame, 
            text="Host IP:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).grid(row=1, column=0, sticky=tk.W, padx=(10, 5))
        
        self.ip_label = tk.Label(
            info_frame, 
            text=self.host_ip, 
            bg="#252526",
            fg="#3794ff",
            font=("Segoe UI", 10, "bold")
        )
        self.ip_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Port selection
        tk.Label(
            info_frame, 
            text="Port:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).grid(row=2, column=0, sticky=tk.W, padx=(10, 5), pady=10)
        
        self.port_entry = tk.Entry(
            info_frame, 
            font=("Segoe UI", 11),
            bg="#3c3c3c",
            fg="white",
            width=10
        )
        self.port_entry.insert(0, "8888")
        self.port_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=10)
        
        # Max clients
        tk.Label(
            info_frame, 
            text="Max Clients:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 10)
        ).grid(row=3, column=0, sticky=tk.W, padx=(10, 5))
        
        self.max_clients_spinbox = tk.Spinbox(
            info_frame, 
            from_=2, 
            to=50, 
            font=("Segoe UI", 11),
            width=10,
            bg="#3c3c3c",
            fg="white"
        )
        self.max_clients_spinbox.delete(0, tk.END)
        self.max_clients_spinbox.insert(0, "10")
        self.max_clients_spinbox.grid(row=3, column=1, sticky=tk.W, padx=5, pady=(0, 15))
        
        # Start server button
        button_frame = tk.Frame(self.root, bg="#1e1e1e")
        button_frame.pack(pady=10)
        
        self.start_btn = tk.Button(
            button_frame,
            text="START SERVER",
            command=self.start_server,
            bg="#0e639c",
            fg="white",
            font=("Segoe UI", 12, "bold"),
            width=15,
            height=2,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="STOP SERVER",
            command=self.stop_server,
            bg="#ca5119",
            fg="white",
            font=("Segoe UI", 12, "bold"),
            width=15,
            height=2,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Join code display (initially hidden)
        self.code_frame = tk.Frame(self.root, bg="#252526")
        
        tk.Label(
            self.code_frame, 
            text="JOIN CODE:", 
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=(10, 5))
        
        self.code_display = tk.Label(
            self.code_frame, 
            text="------", 
            bg="#252526",
            fg="#3794ff",
            font=("Courier", 36, "bold"),
            cursor="hand2"
        )
        self.code_display.pack(pady=5)
        
        tk.Label(
            self.code_frame, 
            text="Share this code with clients", 
            bg="#252526",
            fg="#888888",
            font=("Segoe UI", 10)
        ).pack(pady=(0, 10))
        
        # Connection status
        status_frame = tk.Frame(self.root, bg="#1e1e1e")
        status_frame.pack(pady=10)
        
        self.status_label = tk.Label(
            status_frame, 
            text="● Server Stopped", 
            bg="#1e1e1e",
            fg="#f14c4c",
            font=("Segoe UI", 11, "bold")
        )
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.users_label = tk.Label(
            status_frame, 
            text="Users: 0/10", 
            bg="#1e1e1e",
            fg="#cccccc",
            font=("Segoe UI", 11)
        )
        self.users_label.pack(side=tk.LEFT, padx=5)
        
        # Online users list
        users_frame = tk.Frame(self.root, bg="#252526")
        users_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        tk.Label(
            users_frame, 
            text="CONNECTED USERS", 
            font=("Segoe UI", 12, "bold"),
            bg="#252526",
            fg="#cccccc"
        ).pack(pady=10)
        
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
            yscrollcommand=scrollbar.set,
            relief=tk.FLAT,
            selectbackground="#0e639c"
        )
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.users_listbox.yview)
        
        # Server log
        log_frame = tk.Frame(self.root, bg="#1e1e1e")
        log_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        tk.Label(
            log_frame, 
            text="SERVER LOG", 
            font=("Segoe UI", 12, "bold"),
            bg="#1e1e1e",
            fg="#cccccc"
        ).pack(pady=(0, 10))
        
        # Log text widget
        log_container = tk.Frame(log_frame, bg="#1e1e1e")
        log_container.pack(fill=tk.BOTH, expand=True)
        
        log_scrollbar = tk.Scrollbar(log_container)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(
            log_container,
            bg="#1e1e1e",
            fg="white",
            font=("Consolas", 10),
            height=8,
            yscrollcommand=log_scrollbar.set,
            state=tk.DISABLED,
            relief=tk.FLAT
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scrollbar.config(command=self.log_text.yview)
        
        # Configure tags
        self.log_text.tag_config("info", foreground="#73c991")
        self.log_text.tag_config("warning", foreground="#dcdcaa")
        self.log_text.tag_config("error", foreground="#f14c4c")
        self.log_text.tag_config("system", foreground="#cccccc")
    
    def log_message(self, message, tag="info"):
        """Add message to server log"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def start_server(self):
        """Start the chat server"""
        try:
            port = int(self.port_entry.get())
            if port < 1024 or port > 65535:
                messagebox.showerror("Invalid Port", "Port must be between 1024 and 65535")
                return
            
            self.max_clients = int(self.max_clients_spinbox.get())
            
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
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.DISABLED)
            self.max_clients_spinbox.config(state=tk.DISABLED)
            self.status_label.config(text="● Server Running", fg="#73c991")
            
            # Show code display
            self.code_frame.pack(pady=10, padx=20, fill=tk.X)
            self.code_display.config(text=self.join_code)
            
            # Log initial messages
            self.log_message(f"Server started on port {port}", "info")
            self.log_message(f"Join code: {self.join_code}", "info")
            self.log_message(f"Maximum clients: {self.max_clients}", "info")
            self.log_message(f"Server IP: {self.host_ip}", "info")
            
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
                if len(self.client_sockets) >= self.max_clients:
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
                
                # Add to users list
                self.users_list.append(f"{client_username}@{client_address[0]}")
                self.update_users_list()
                
                # Update users count
                self.users_label.config(text=f"Users: {len(self.client_sockets)}/{self.max_clients}")
                
                # Send welcome to client
                welcome_msg = json.dumps({
                    'type': 'system',
                    'message': f'Welcome to the chat! Connected to server.'
                })
                self.send_to_client(client_socket, welcome_msg)
                
                # Send current user list to client
                user_list_msg = json.dumps({
                    'type': 'user_list',
                    'users': self.users_list
                })
                self.send_to_client(client_socket, user_list_msg)
                
                # Log connection
                self.log_message(f"{client_username} connected from {client_address[0]}", "info")
                
                # Broadcast new user joined
                join_msg = json.dumps({
                    'type': 'system',
                    'message': f'{client_username} has joined the chat'
                })
                self.broadcast_message(join_msg, exclude_socket=client_socket)
                
                # Start thread to handle this client
                threading.Thread(target=self.handle_client, args=(client_info,), daemon=True).start()
                
            except Exception as e:
                if self.running:
                    self.log_message(f"Error accepting client: {e}", "error")
    
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
                            self.log_message(f"{username}: {message}", "system")
                            
                    elif message_type == 'typing':
                        # Broadcast typing indicator
                        typing_msg = json.dumps({
                            'type': 'typing',
                            'username': username
                        })
                        self.broadcast_message(typing_msg, exclude_socket=client_socket)
                        
                except json.JSONDecodeError:
                    # Handle plain text
                    message = data.decode().strip()
                    if message:
                        broadcast_msg = json.dumps({
                            'type': 'message',
                            'username': username,
                            'message': message,
                            'timestamp': datetime.now().strftime("%H:%M:%S")
                        })
                        self.broadcast_message(broadcast_msg, exclude_socket=client_socket)
                        self.log_message(f"{username}: {message}", "system")
                
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
            self.users_label.config(text=f"Users: {len(self.client_sockets)}/{self.max_clients}")
            
            # Log disconnection
            self.log_message(f"{username} disconnected", "warning")
            
            # Broadcast user left
            leave_msg = json.dumps({
                'type': 'system',
                'message': f'{username} has left the chat'
            })
            self.broadcast_message(leave_msg)
            
            # Close socket
            client_socket.close()
            
        except Exception as e:
            self.log_message(f"Error removing client: {e}", "error")
    
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
    
    def update_users_list(self):
        """Update the users list display"""
        self.users_listbox.delete(0, tk.END)
        for user in self.users_list:
            display_name = user.split('@')[0]
            self.users_listbox.insert(tk.END, display_name)
    
    def stop_server(self):
        """Stop the chat server"""
        self.running = False
        
        # Disconnect all clients
        for client in self.client_sockets:
            try:
                client['socket'].close()
            except:
                pass
        self.client_sockets.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        # Reset UI
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.NORMAL)
        self.max_clients_spinbox.config(state=tk.NORMAL)
        self.status_label.config(text="● Server Stopped", fg="#f14c4c")
        self.users_label.config(text=f"Users: 0/{self.max_clients}")
        self.code_frame.pack_forget()
        
        # Clear lists
        self.users_list = []
        self.update_users_list()
        
        # Log stop
        self.log_message("Server stopped", "info")
        
        # Reset running flag
        self.running = True
    
    def on_closing(self):
        """Handle window closing"""
        if self.server_socket:
            if messagebox.askyesno("Quit", "Are you sure you want to quit? This will stop the server and disconnect all clients."):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = HostApp()
    app.run()
