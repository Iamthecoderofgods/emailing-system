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

# ============================================
# SERVER COMPONENT
# ============================================

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.setup_database()
        
    def setup_database(self):
        """Setup SQLite database for user accounts"""
        self.conn = sqlite3.connect(':memory:', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users
                             (id INTEGER PRIMARY KEY AUTOINCREMENT,
                              username TEXT UNIQUE,
                              password TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS messages
                             (id INTEGER PRIMARY KEY AUTOINCREMENT,
                              sender TEXT,
                              message TEXT,
                              timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        self.conn.commit()
        
        test_users = [('admin', 'admin123'), ('user1', 'password1'), ('user2', 'password2')]
        for username, password in test_users:
            try:
                hashed_password = sha256(password.encode()).hexdigest()
                self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                                  (username, hashed_password))
            except:
                pass
        self.conn.commit()
    
    def get_uptime(self):
        """Get server uptime in human readable format"""
        uptime_seconds = int(time.time() - self.start_time)
        days = uptime_seconds // (24 * 3600)
        uptime_seconds %= (24 * 3600)
        hours = uptime_seconds // 3600
        uptime_seconds %= 3600
        minutes = uptime_seconds // 60
        seconds = uptime_seconds % 60
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def hash_password(self, password):
        return sha256(password.encode()).hexdigest()
    
    def register_user(self, username, password):
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                              (username, hashed_password))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def authenticate_user(self, username, password):
        hashed_password = self.hash_password(password)
        self.cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
                          (username, hashed_password))
        return self.cursor.fetchone() is not None
    
    def save_message(self, sender, message):
        self.cursor.execute('''INSERT INTO messages (sender, message) VALUES (?, ?)''',
                          (sender, message))
        self.conn.commit()
    
    def get_message_history(self, count=50):
        self.cursor.execute('''SELECT sender, message, timestamp FROM messages 
                             ORDER BY timestamp DESC LIMIT ?''', (count,))
        return self.cursor.fetchall()
    
    def broadcast_user_list(self, exclude_socket=None):
        """Send updated user list to all connected clients"""
        with self.lock:
            users = list(self.clients.values())
            user_list_message = {
                'type': 'users_list',
                'users': users
            }
            for client_socket in list(self.clients.keys()):
                if client_socket != exclude_socket:
                    try:
                        client_socket.send(json.dumps(user_list_message).encode('utf-8'))
                    except:
                        self.remove_client(client_socket)
    
    def broadcast(self, message, exclude_socket=None):
        """Send message to all connected clients except the sender"""
        with self.lock:
            for client_socket in list(self.clients.keys()):
                if client_socket != exclude_socket:
                    try:
                        client_socket.send(message.encode('utf-8'))
                    except:
                        self.remove_client(client_socket)
    
    def handle_client(self, client_socket, address):
        username = None
        try:
            while True:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                    
                data = json.loads(message)
                
                if data['type'] == 'register':
                    success = self.register_user(data['username'], data['password'])
                    response = {
                        'type': 'register',
                        'success': success,
                        'message': 'Registration successful!' if success else 'Username already exists!'
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                        
                elif data['type'] == 'login':
                    if self.authenticate_user(data['username'], data['password']):
                        username = data['username']
                        with self.lock:
                            self.clients[client_socket] = username
                        
                        # Get message history
                        history = self.get_message_history()
                        response = {
                            'type': 'login',
                            'success': True,
                            'username': username,
                            'history': history,
                            'users': list(self.clients.values())  # Send current users to new user
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        
                        # Notify ALL other users about new user AND send updated user list
                        notification = {
                            'type': 'notification',
                            'message': f'{username} has joined the chat!'
                        }
                        self.broadcast(json.dumps(notification), exclude_socket=client_socket)
                        
                        # Broadcast updated user list to ALL users (including the new one)
                        self.broadcast_user_list()
                        
                    else:
                        response = {
                            'type': 'login',
                            'success': False,
                            'message': 'Invalid credentials!'
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        
                elif data['type'] == 'message' and username:
                    self.save_message(username, data['message'])
                    message_data = {
                        'type': 'message',
                        'sender': username,
                        'message': data['message'],
                        'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
                    }
                    self.broadcast(json.dumps(message_data), exclude_socket=client_socket)
                    
                elif data['type'] == 'private' and username:
                    receiver = data['receiver']
                    message_data = {
                        'type': 'private',
                        'sender': username,
                        'receiver': receiver,
                        'message': data['message'],
                        'timestamp': datetime.datetime.now().strftime('%H:%M:%S')
                    }
                    
                    with self.lock:
                        for sock, user in self.clients.items():
                            if user == receiver:
                                sock.send(json.dumps(message_data).encode('utf-8'))
                                break
                    
                    client_socket.send(json.dumps(message_data).encode('utf-8'))
                    
                elif data['type'] == 'get_users' and username:
                    with self.lock:
                        users = list(self.clients.values())
                    response = {
                        'type': 'users_list',
                        'users': users
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                
                elif data['type'] == 'uptime':
                    with self.lock:
                        online_count = len(self.clients)
                    response = {
                        'type': 'uptime',
                        'uptime': self.get_uptime(),
                        'start_time': datetime.datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
                        'online_users': online_count
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                        
        except Exception as e:
            print(f"Error with client {address}: {e}")
        finally:
            if username:
                with self.lock:
                    if client_socket in self.clients:
                        del self.clients[client_socket]
                    notification = {
                        'type': 'notification',
                        'message': f'{username} has left the chat!'
                    }
                    self.broadcast(json.dumps(notification))
                    
                    # Update user list for remaining users
                    self.broadcast_user_list()
                    
            client_socket.close()
    
    def remove_client(self, client_socket):
        with self.lock:
            if client_socket in self.clients:
                username = self.clients[client_socket]
                del self.clients[client_socket]
                print(f"{username} disconnected")
    
    def start_server_in_thread(self):
        def run_server():
            self.server.bind((self.host, self.port))
            self.server.listen()
            print(f"Chat server started on {self.host}:{self.port}")
            print(f"Server start time: {datetime.datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}")
            
            try:
                while True:
                    client_socket, address = self.server.accept()
                    print(f"New connection from {address}")
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
            except Exception as e:
                print(f"Server error: {e}")
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

# ============================================
# CLIENT COMPONENT
# ============================================

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat Messenger")
        self.root.geometry("900x700")
        self.root.configure(bg='#2C3E50')
        
        self.server = ChatServer()
        self.server.start_server_in_thread()
        
        self.client_socket = None
        self.connected = False
        self.username = None
        self.message_queue = queue.Queue()
        
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
        self.start_message_handler()
        
    def setup_ui(self):
        self.title_font = font.Font(family="Helvetica", size=24, weight="bold")
        self.text_font = font.Font(family="Arial", size=11)
        self.message_font = font.Font(family="Arial", size=10)
        
        self.main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.colors['secondary'], 
                       foreground=self.colors['fg'], padding=[10, 5])
        style.map('TNotebook.Tab', background=[('selected', self.colors['accent'])])
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.login_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(self.login_tab, text='Login / Register')
        self.setup_login_tab()
        
        self.chat_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(self.chat_tab, text='Chat Room')
        self.setup_chat_tab()
        
        self.notebook.hide(1)
        self.connect_to_server()
    
    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server.host, self.server.port))
            self.connected = True
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", "Failed to connect to server")
    
    def setup_login_tab(self):
        title_frame = tk.Frame(self.login_tab, bg=self.colors['bg'])
        title_frame.pack(pady=(30, 20))
        
        title_label = tk.Label(title_frame, text="SecureChat", 
                              font=self.title_font, 
                              bg=self.colors['bg'], 
                              fg=self.colors['accent'])
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Secure Online Messaging", 
                                 font=("Arial", 12), 
                                 bg=self.colors['bg'], 
                                 fg=self.colors['fg'])
        subtitle_label.pack(pady=5)
        
        login_frame = tk.Frame(self.login_tab, bg=self.colors['secondary'], 
                              relief=tk.RAISED, bd=2)
        login_frame.pack(padx=80, pady=20, fill=tk.X)
        
        tk.Label(login_frame, text="Username:", bg=self.colors['secondary'], 
                fg=self.colors['fg'], font=self.text_font).grid(row=0, column=0, 
                                                              padx=20, pady=15, sticky='w')
        self.username_entry = tk.Entry(login_frame, font=self.text_font, 
                                      width=30, bg='white', fg='black')
        self.username_entry.grid(row=0, column=1, padx=20, pady=15, sticky='ew')
        self.username_entry.insert(0, "user1")
        
        tk.Label(login_frame, text="Password:", bg=self.colors['secondary'], 
                fg=self.colors['fg'], font=self.text_font).grid(row=1, column=0, 
                                                              padx=20, pady=15, sticky='w')
        self.password_entry = tk.Entry(login_frame, font=self.text_font, 
                                      width=30, bg='white', fg='black', 
                                      show="•")
        self.password_entry.grid(row=1, column=1, padx=20, pady=15, sticky='ew')
        self.password_entry.insert(0, "password1")
        
        button_frame = tk.Frame(login_frame, bg=self.colors['secondary'])
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        self.login_btn = tk.Button(button_frame, text="Login", 
                                  command=self.login, 
                                  bg=self.colors['accent'], 
                                  fg='white',
                                  font=self.text_font,
                                  width=15,
                                  relief=tk.RAISED,
                                  bd=2)
        self.login_btn.pack(side=tk.LEFT, padx=10)
        
        self.register_btn = tk.Button(button_frame, text="Register", 
                                     command=self.register, 
                                     bg=self.colors['success'], 
                                     fg='white',
                                     font=self.text_font,
                                     width=15,
                                     relief=tk.RAISED,
                                     bd=2)
        self.register_btn.pack(side=tk.LEFT, padx=10)
        
        self.login_status = tk.Label(self.login_tab, text="", 
                                    bg=self.colors['bg'], 
                                    fg=self.colors['warning'],
                                    font=self.text_font)
        self.login_status.pack(pady=10)
        
        test_frame = tk.Frame(self.login_tab, bg=self.colors['bg'])
        test_frame.pack(pady=20)
        
        test_label = tk.Label(test_frame, text="Test Credentials:", 
                             bg=self.colors['bg'], fg=self.colors['fg'],
                             font=("Arial", 10, "italic"))
        test_label.pack()
        
        test_text = tk.Label(test_frame, 
                            text="user1/password1 | user2/password2 | admin/admin123",
                            bg=self.colors['bg'], fg=self.colors['accent'],
                            font=("Arial", 9))
        test_text.pack()
    
    def setup_chat_tab(self):
        top_frame = tk.Frame(self.chat_tab, bg=self.colors['secondary'])
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.user_label = tk.Label(top_frame, text="Not logged in", 
                                  bg=self.colors['secondary'], 
                                  fg=self.colors['fg'],
                                  font=self.text_font)
        self.user_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.uptime_btn = tk.Button(top_frame, text="🖥️ Server Info", 
                                   command=self.get_server_uptime,
                                   bg=self.colors['accent'], 
                                   fg='white',
                                   font=self.text_font,
                                   relief=tk.RAISED)
        self.uptime_btn.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.users_btn = tk.Button(top_frame, text="🔄 Refresh Users", 
                                  command=self.get_online_users,
                                  bg=self.colors['accent'], 
                                  fg='white',
                                  font=self.text_font,
                                  relief=tk.RAISED)
        self.users_btn.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.logout_btn = tk.Button(top_frame, text="Logout", 
                                   command=self.logout,
                                   bg=self.colors['warning'], 
                                   fg='white',
                                   font=self.text_font,
                                   relief=tk.RAISED)
        self.logout_btn.pack(side=tk.RIGHT, padx=10, pady=5)
        
        chat_frame = tk.Frame(self.chat_tab, bg=self.colors['bg'])
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.message_display = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD,
            bg=self.colors['message_bg'],
            fg=self.colors['message_fg'],
            font=self.message_font,
            state='disabled',
            height=20
        )
        self.message_display.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        bottom_frame = tk.Frame(self.chat_tab, bg=self.colors['secondary'])
        bottom_frame.pack(fill=tk.X, padx=5, pady=5)
        
        type_frame = tk.Frame(bottom_frame, bg=self.colors['secondary'])
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(type_frame, text="Send to:", bg=self.colors['secondary'], 
                fg=self.colors['fg']).pack(side=tk.LEFT)
        
        self.message_type = tk.StringVar(value="public")
        tk.Radiobutton(type_frame, text="Everyone", variable=self.message_type, 
                      value="public", bg=self.colors['secondary'], 
                      fg=self.colors['fg']).pack(side=tk.LEFT, padx=10)
        
        tk.Radiobutton(type_frame, text="Private:", variable=self.message_type, 
                      value="private", bg=self.colors['secondary'], 
                      fg=self.colors['fg']).pack(side=tk.LEFT, padx=10)
        
        self.recipient_var = tk.StringVar()
        self.recipient_combo = ttk.Combobox(type_frame, 
                                          textvariable=self.recipient_var,
                                          state='readonly',
                                          width=15)
        self.recipient_combo.pack(side=tk.LEFT, padx=5)
        
        input_frame = tk.Frame(bottom_frame, bg=self.colors['secondary'])
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.message_input = tk.Text(input_frame, height=3, 
                                    bg='white', fg='black',
                                    font=self.message_font)
        self.message_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.send_btn = tk.Button(input_frame, text="Send", 
                                 command=self.send_message,
                                 bg=self.colors['success'], 
                                 fg='white',
                                 font=self.text_font,
                                 height=3,
                                 width=10,
                                 relief=tk.RAISED)
        self.send_btn.pack(side=tk.RIGHT)
        
        users_frame = tk.Frame(self.chat_tab, bg=self.colors['secondary'])
        users_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(users_frame, text="Online Users:", bg=self.colors['secondary'], 
                fg=self.colors['fg'], font=self.text_font).pack(anchor='w', padx=10, pady=5)
        
        self.users_listbox = tk.Listbox(users_frame, 
                                       bg=self.colors['message_bg'],
                                       fg=self.colors['message_fg'],
                                       font=self.message_font,
                                       height=4)
        self.users_listbox.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.message_input.bind("<Return>", lambda e: self.send_message())
        self.message_input.bind("<Shift-Return>", 
                               lambda e: self.message_input.insert(tk.INSERT, '\n'))
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.login_status.config(text="Please enter username and password!")
            return
            
        login_data = {
            'type': 'login',
            'username': username,
            'password': password
        }
        
        try:
            self.client_socket.send(json.dumps(login_data).encode('utf-8'))
            self.login_status.config(text="Logging in...")
        except:
            self.login_status.config(text="Connection error!")
    
    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            self.login_status.config(text="Please enter username and password!")
            return
            
        register_data = {
            'type': 'register',
            'username': username,
            'password': password
        }
        
        try:
            self.client_socket.send(json.dumps(register_data).encode('utf-8'))
            self.login_status.config(text="Registering...")
        except:
            self.login_status.config(text="Connection error!")
    
    def logout(self):
        self.username = None
        self.notebook.select(0)
        self.notebook.hide(1)
        self.message_display.config(state='normal')
        self.message_display.delete(1.0, tk.END)
        self.message_display.config(state='disabled')
        self.user_label.config(text="Not logged in")
        self.users_listbox.delete(0, tk.END)
    
    def send_message(self):
        if not self.username:
            messagebox.showwarning("Not Logged In", "Please login first!")
            return
            
        message = self.message_input.get(1.0, tk.END).strip()
        if not message:
            return
            
        message_type = self.message_type.get()
        
        if message_type == 'private':
            recipient = self.recipient_var.get()
            if not recipient:
                messagebox.showwarning("No Recipient", "Please select a recipient!")
                return
                
            message_data = {
                'type': 'private',
                'receiver': recipient,
                'message': message
            }
            
            self.display_message(f"You → {recipient}: {message}", "you")
        else:
            message_data = {
                'type': 'message',
                'message': message
            }
            
            self.display_message(f"You: {message}", "you")
        
        try:
            self.client_socket.send(json.dumps(message_data).encode('utf-8'))
        except:
            messagebox.showerror("Error", "Failed to send message!")
        
        self.message_input.delete(1.0, tk.END)
    
    def get_server_uptime(self):
        if self.username:
            request = {'type': 'uptime'}
            try:
                self.client_socket.send(json.dumps(request).encode('utf-8'))
            except:
                messagebox.showerror("Error", "Failed to contact server")
    
    def get_online_users(self):
        if self.username:
            request = {'type': 'get_users'}
            try:
                self.client_socket.send(json.dumps(request).encode('utf-8'))
            except:
                pass
    
    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    self.message_queue.put(message)
            except:
                break
    
    def start_message_handler(self):
        def process_queue():
            try:
                while True:
                    message = self.message_queue.get_nowait()
                    self.handle_server_message(message)
            except queue.Empty:
                pass
            self.root.after(100, process_queue)
        
        self.root.after(100, process_queue)
    
    def handle_server_message(self, message):
        try:
            data = json.loads(message)
            
            if data['type'] == 'login':
                if data['success']:
                    self.username = data['username']
                    self.user_label.config(text=f"Logged in as: {self.username}")
                    self.login_status.config(text="Login successful!", fg=self.colors['success'])
                    
                    self.notebook.select(1)
                    self.notebook.hide(0)
                    
                    self.message_display.config(state='normal')
                    self.message_display.insert(tk.END, f"=== Welcome {self.username} ===\n\n")
                    if 'history' in data:
                        for sender, msg, timestamp in reversed(data['history']):
                            self.display_message(f"{sender}: {msg}", "history")
                    self.message_display.config(state='disabled')
                    self.message_display.see(tk.END)
                    
                    # Update user list from login response
                    if 'users' in data:
                        self.update_users_list(data['users'])
                    
                else:
                    self.login_status.config(text=data['message'], fg=self.colors['warning'])
                    
            elif data['type'] == 'register':
                if data['success']:
                    self.login_status.config(text=data['message'], fg=self.colors['success'])
                else:
                    self.login_status.config(text=data['message'], fg=self.colors['warning'])
                    
            elif data['type'] == 'message':
                self.display_message(f"{data['sender']}: {data['message']}", "other")
                
            elif data['type'] == 'private':
                if data['receiver'] == self.username or data['sender'] == self.username:
                    prefix = f"{data['sender']} → {data['receiver']}"
                    self.display_message(f"{prefix}: {data['message']}", "private")
                
            elif data['type'] == 'notification':
                self.display_message(f"⚡ {data['message']}", "notification")
                    
            elif data['type'] == 'users_list':
                self.update_users_list(data['users'])
                
            elif data['type'] == 'uptime':
                messagebox.showinfo(
                    "Server Information",
                    f"🚀 Server Started: {data['start_time']}\n"
                    f"⏱️  Uptime: {data['uptime']}\n"
                    f"👥 Online Users: {data['online_users']}\n"
                    f"🌐 Server: {self.server.host}:{self.server.port}"
                )
                
        except Exception as e:
            print(f"Error handling message: {e}")
    
    def display_message(self, message, msg_type):
        self.message_display.config(state='normal')
        
        if not self.message_display.tag_names():
            self.message_display.tag_config("you", foreground="#2980B9", font=("Arial", 10, "bold"))
            self.message_display.tag_config("other", foreground="#2C3E50")
            self.message_display.tag_config("private", foreground="#8E44AD", font=("Arial", 10, "italic"))
            self.message_display.tag_config("notification", foreground="#E67E22", font=("Arial", 9))
            self.message_display.tag_config("history", foreground="#7F8C8D", font=("Arial", 9))
        
        self.message_display.insert(tk.END, f"{message}\n", msg_type)
        self.message_display.config(state='disabled')
        self.message_display.see(tk.END)
    
    def update_users_list(self, users):
        self.users_listbox.delete(0, tk.END)
        
        # Show all users, highlight yourself
        for user in users:
            if user == self.username:
                self.users_listbox.insert(tk.END, f"● {user} (you)")
            else:
                self.users_listbox.insert(tk.END, f"● {user}")
        
        # Update recipient dropdown (exclude yourself)
        other_users = [user for user in users if user != self.username]
        self.recipient_combo['values'] = other_users
        if other_users and not self.recipient_var.get():
            self.recipient_var.set(other_users[0])

# ============================================
# MAIN APPLICATION
# ============================================

def main():
    root = tk.Tk()
    app = ChatClientGUI(root)
    
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()