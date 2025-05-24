import sys
import sqlite3
import mysql.connector
import psycopg2
import pyotp
import bcrypt
import pyperclip
import json
import os
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QSystemTrayIcon, QMenu, QMessageBox, QComboBox, QDialog, QFormLayout,
                             QTableWidget, QTableWidgetItem, QInputDialog, QAction)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QIcon
import uuid
from datetime import datetime
import platform
from PIL import Image, ImageDraw
import threading
import pystray
from pystray import Menu, MenuItem as Item

# Verifica se o sistema é Windows
if platform.system() != "Windows":
    print("Este aplicativo só funciona no Windows.")
    sys.exit(1)

# Gerenciamento da chave de criptografia
KEY_FILE = "encryption_key.key"

# Carrega ou gera a chave de criptografia
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(ENCRYPTION_KEY)

CIPHER = Fernet(ENCRYPTION_KEY)

# Função para regenerar a chave de criptografia e atualizar o CIPHER
def regenerate_encryption_key():
    global ENCRYPTION_KEY, CIPHER
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(ENCRYPTION_KEY)
    CIPHER = Fernet(ENCRYPTION_KEY)

class Database:
    def __init__(self, db_type, **kwargs):
        self.db_type = db_type
        self.conn = sqlite3.connect("authenticator.db")  # Banco SQLite como base local
        self.server_conn = None  # Conexão opcional com MySQL ou PostgreSQL
        self.create_local_tables()

        # Carregar a configuração anterior para detectar mudanças
        config_file = "config.json"
        previous_db_type = "sqlite"  # Padrão se não houver arquivo
        if os.path.exists(config_file):
            try:
                with open(config_file, 'rb') as f:
                    encrypted_config = f.read()
                previous_config = json.loads(CIPHER.decrypt(encrypted_config).decode())
                previous_db_type = previous_config.get("db_type", "sqlite")
            except Exception:
                pass

        # Configuração opcional do servidor (MySQL ou PostgreSQL)
        if db_type in ["mysql", "postgres"]:
            try:
                if db_type == "mysql":
                    self.server_conn = mysql.connector.connect(
                        host=kwargs.get("host"),
                        user=kwargs.get("user"),
                        password=kwargs.get("password"),
                        port=kwargs.get("port", 3306),
                        database=kwargs.get("database", "authenticator")
                    )
                    self.create_server_tables("mysql")
                elif db_type == "postgres":
                    self.server_conn = psycopg2.connect(
                        host=kwargs.get("host"),
                        user=kwargs.get("user"),
                        password=kwargs.get("password"),
                        port=kwargs.get("port", 5432),
                        database=kwargs.get("database", "authenticator")
                    )
                    self.create_server_tables("postgres")
            except (mysql.connector.Error, psycopg2.Error) as err:
                QMessageBox.warning(None, "Aviso", f"Não foi possível conectar ao servidor: {err}. Usando SQLite localmente.")
                self.server_conn = None

        # Sincronizar dados ao inicializar, considerando a troca de servidor
        if self.server_conn:
            self.synchronize_data()
            if previous_db_type != db_type and previous_db_type != "sqlite":
                QMessageBox.information(None, "Informação", f"Tipo de banco alterado de {previous_db_type} para {db_type}. Dados sincronizados.")

    def create_local_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                                               id TEXT PRIMARY KEY,
                                                               username TEXT UNIQUE,
                                                               email TEXT,
                                                               password TEXT,
                                                               user_type TEXT,
                                                               last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                          )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS totp_secrets (
                                                                      id TEXT PRIMARY KEY,
                                                                      user_id TEXT,
                                                                      secret TEXT,
                                                                      label TEXT,
                                                                      is_default BOOLEAN,
                                                                      last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                      FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS sync_log (
                                                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                                  last_sync_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                          )''')
        self.conn.commit()

    def create_server_tables(self, db_type):
        if not self.server_conn:
            return
        server_cursor = self.server_conn.cursor()
        try:
            if db_type == "mysql":
                server_cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                                                              id VARCHAR(36) PRIMARY KEY,
                    username VARCHAR(255) UNIQUE,
                    email VARCHAR(255),
                    password VARCHAR(255),
                    user_type VARCHAR(50),
                    last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
                    )''')
                server_cursor.execute('''CREATE TABLE IF NOT EXISTS totp_secrets (
                                                                                     id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36),
                    secret VARCHAR(255),
                    label VARCHAR(255),
                    is_default TINYINT,
                    last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    )''')
            elif db_type == "postgres":
                server_cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                                                              id UUID PRIMARY KEY,
                                                                              username VARCHAR(255) UNIQUE,
                    email VARCHAR(255),
                    password VARCHAR(255),
                    user_type VARCHAR(50),
                    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
                server_cursor.execute('''CREATE TABLE IF NOT EXISTS totp_secrets (
                                                                                     id UUID PRIMARY KEY,
                                                                                     user_id UUID,
                                                                                     secret VARCHAR(255),
                    label VARCHAR(255),
                    is_default BOOLEAN,
                    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    )''')
            self.server_conn.commit()
        except Exception as e:
            QMessageBox.warning(None, "Aviso", f"Erro ao criar tabelas no servidor: {e}")
        finally:
            server_cursor.close()

    def get_last_sync_time(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT last_sync_time FROM sync_log ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        cursor.close()
        return result[0] if result else "2000-01-01 00:00:00"

    def update_last_sync_time(self):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO sync_log (last_sync_time) VALUES (CURRENT_TIMESTAMP)")
        self.conn.commit()
        cursor.close()

    def synchronize_data(self):
        if not self.server_conn:
            print("Sincronização não realizada: Sem conexão com o servidor.")
            return False

        cursor = self.conn.cursor()
        server_cursor = self.server_conn.cursor()

        try:
            # Obter todos os IDs dos usuários no SQLite local
            cursor.execute("SELECT id FROM users")
            local_user_ids = set(row[0] for row in cursor.fetchall())
            print(f"IDs de usuários no SQLite local: {local_user_ids}")

            # Obter todos os usuários do servidor
            server_cursor.execute("SELECT id, username, email, password, user_type, last_modified FROM users")
            server_users = {row[0]: row for row in server_cursor.fetchall()}
            print(f"Usuários no servidor: {len(server_users)}")

            # Obter todos os usuários do SQLite local
            cursor.execute("SELECT id, username, email, password, user_type, last_modified FROM users")
            local_users = {row[0]: row for row in cursor.fetchall()}
            print(f"Usuários no SQLite local: {len(local_users)}")

            # Sincronizar usuários
            # - Do servidor para o local
            for user_id, server_user in server_users.items():
                local_user = local_users.get(user_id)
                server_last_modified = server_user[5]
                if local_user:
                    local_last_modified = datetime.strptime(local_user[5], '%Y-%m-%d %H:%M:%S')
                    if server_last_modified > local_last_modified:
                        print(f"Sincronizando usuário do servidor para o local: {user_id}")
                        cursor.execute("INSERT OR REPLACE INTO users (id, username, email, password, user_type, last_modified) VALUES (?, ?, ?, ?, ?, ?)",
                                       server_user[:5] + (server_last_modified.strftime('%Y-%m-%d %H:%M:%S'),))
                else:
                    # Novo usuário no servidor
                    print(f"Sincronizando novo usuário do servidor para o local: {user_id}")
                    cursor.execute("INSERT OR REPLACE INTO users (id, username, email, password, user_type, last_modified) VALUES (?, ?, ?, ?, ?, ?)",
                                   server_user[:5] + (server_last_modified.strftime('%Y-%m-%d %H:%M:%S'),))

            # - Do local para o servidor (incluindo exclusões)
            for user_id, local_user in local_users.items():
                server_user = server_users.get(user_id)
                local_last_modified = datetime.strptime(local_user[5], '%Y-%m-%d %H:%M:%S')
                if not server_user:
                    # Usuário excluído no servidor ou novo no local
                    print(f"Sincronizando exclusão ou novo usuário do local para o servidor: {user_id}")
                    server_query = "INSERT INTO users (id, username, email, password, user_type, last_modified) VALUES (%s, %s, %s, %s, %s, %s)"
                    if self.db_type == "mysql":
                        server_query += " ON DUPLICATE KEY UPDATE username=VALUES(username), email=VALUES(email), password=VALUES(password), user_type=VALUES(user_type), last_modified=VALUES(last_modified)"
                        server_params = local_user
                    elif self.db_type == "postgres":
                        server_query += " ON CONFLICT (id) DO UPDATE SET username=EXCLUDED.username, email=EXCLUDED.email, password=EXCLUDED.password, user_type=EXCLUDED.user_type, last_modified=EXCLUDED.last_modified"
                        server_params = local_user
                    server_cursor.execute(server_query, server_params)
                else:
                    # Comparar last_modified
                    server_last_modified = server_user[5]
                    if local_last_modified > server_last_modified:
                        print(f"Sincronizando usuário atualizado do local para o servidor: {user_id}")
                        server_query = "INSERT INTO users (id, username, email, password, user_type, last_modified) VALUES (%s, %s, %s, %s, %s, %s)"
                        if self.db_type == "mysql":
                            server_query += " ON DUPLICATE KEY UPDATE username=VALUES(username), email=VALUES(email), password=VALUES(password), user_type=VALUES(user_type), last_modified=VALUES(last_modified)"
                            server_params = local_user
                        elif self.db_type == "postgres":
                            server_query += " ON CONFLICT (id) DO UPDATE SET username=EXCLUDED.username, email=EXCLUDED.email, password=EXCLUDED.password, user_type=EXCLUDED.user_type, last_modified=EXCLUDED.last_modified"
                            server_params = local_user
                        server_cursor.execute(server_query, server_params)

            # Detectar exclusões no local e propagar para o servidor
            for user_id in local_user_ids - set(local_users.keys()):
                if user_id in server_users:
                    print(f"Detectada exclusão local de usuário {user_id}. Excluindo do servidor.")
                    server_cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                    server_cursor.execute("DELETE FROM totp_secrets WHERE user_id = %s", (user_id,))

            # Sincronizar tabela 'totp_secrets'
            # Obter todos os IDs dos segredos TOTP no SQLite local
            cursor.execute("SELECT id FROM totp_secrets")
            local_secret_ids = set(row[0] for row in cursor.fetchall())
            print(f"IDs de segredos TOTP no SQLite local: {local_secret_ids}")

            # Obter todos os segredos TOTP do servidor
            server_cursor.execute("SELECT id, user_id, secret, label, is_default, last_modified FROM totp_secrets")
            server_secrets = {row[0]: row for row in server_cursor.fetchall()}
            print(f"Segredos TOTP no servidor: {len(server_secrets)}")

            # Obter todos os segredos TOTP do SQLite local
            cursor.execute("SELECT id, user_id, secret, label, is_default, last_modified FROM totp_secrets")
            local_secrets = {row[0]: row for row in cursor.fetchall()}
            print(f"Segredos TOTP no SQLite local: {len(local_secrets)}")

            # Sincronizar segredos TOTP
            # - Do servidor para o local
            for secret_id, server_secret in server_secrets.items():
                local_secret = local_secrets.get(secret_id)
                server_last_modified = server_secret[5]
                if local_secret:
                    local_last_modified = datetime.strptime(local_secret[5], '%Y-%m-%d %H:%M:%S')
                    if server_last_modified > local_last_modified:
                        print(f"Sincronizando segredo TOTP do servidor para o local: {secret_id}")
                        cursor.execute("INSERT OR REPLACE INTO totp_secrets (id, user_id, secret, label, is_default, last_modified) VALUES (?, ?, ?, ?, ?, ?)",
                                       server_secret[:5] + (server_last_modified.strftime('%Y-%m-%d %H:%M:%S'),))
                else:
                    # Novo segredo no servidor
                    print(f"Sincronizando novo segredo TOTP do servidor para o local: {secret_id}")
                    cursor.execute("INSERT OR REPLACE INTO totp_secrets (id, user_id, secret, label, is_default, last_modified) VALUES (?, ?, ?, ?, ?, ?)",
                                   server_secret[:5] + (server_last_modified.strftime('%Y-%m-%d %H:%M:%S'),))

            # - Do local para o servidor
            for secret_id, local_secret in local_secrets.items():
                server_secret = server_secrets.get(secret_id)
                local_last_modified = datetime.strptime(local_secret[5], '%Y-%m-%d %H:%M:%S')
                if not server_secret:
                    # Novo segredo no SQLite
                    print(f"Sincronizando novo segredo TOTP do local para o servidor: {secret_id}")
                    server_query = "INSERT INTO totp_secrets (id, user_id, secret, label, is_default, last_modified) VALUES (%s, %s, %s, %s, %s, %s)"
                    if self.db_type == "mysql":
                        is_default = 1 if local_secret[4] else 0
                        server_query += " ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), secret=VALUES(secret), label=VALUES(label), is_default=VALUES(is_default), last_modified=VALUES(last_modified)"
                        server_params = (local_secret[0], local_secret[1], local_secret[2], local_secret[3], is_default, local_secret[5])
                    elif self.db_type == "postgres":
                        server_query += " ON CONFLICT (id) DO UPDATE SET user_id=EXCLUDED.user_id, secret=EXCLUDED.secret, label=EXCLUDED.label, is_default=EXCLUDED.is_default, last_modified=EXCLUDED.last_modified"
                        server_params = (local_secret[0], local_secret[1], local_secret[2], local_secret[3], local_secret[4], local_secret[5])
                    server_cursor.execute(server_query, server_params)
                else:
                    # Comparar last_modified
                    server_last_modified = server_secret[5]
                    if local_last_modified > server_last_modified:
                        print(f"Sincronizando segredo TOTP atualizado do local para o servidor: {secret_id}")
                        server_query = "INSERT INTO totp_secrets (id, user_id, secret, label, is_default, last_modified) VALUES (%s, %s, %s, %s, %s, %s)"
                        if self.db_type == "mysql":
                            is_default = 1 if local_secret[4] else 0
                            server_query += " ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), secret=VALUES(secret), label=VALUES(label), is_default=VALUES(is_default), last_modified=VALUES(last_modified)"
                            server_params = (local_secret[0], local_secret[1], local_secret[2], local_secret[3], is_default, local_secret[5])
                        elif self.db_type == "postgres":
                            server_query += " ON CONFLICT (id) DO UPDATE SET user_id=EXCLUDED.user_id, secret=EXCLUDED.secret, label=EXCLUDED.label, is_default=EXCLUDED.is_default, last_modified=EXCLUDED.last_modified"
                            server_params = (local_secret[0], local_secret[1], local_secret[2], local_secret[3], local_secret[4], local_secret[5])
                        server_cursor.execute(server_query, server_params)

            # Detectar exclusões no local e propagar para o servidor
            for secret_id in local_secret_ids - set(local_secrets.keys()):
                if secret_id in server_secrets:
                    print(f"Detectada exclusão local de segredo TOTP {secret_id}. Excluindo do servidor.")
                    server_cursor.execute("DELETE FROM totp_secrets WHERE id = %s", (secret_id,))

            self.conn.commit()
            self.server_conn.commit()
            self.update_last_sync_time()
            print("Sincronização concluída com sucesso.")
            return True
        except Exception as e:
            print(f"Erro ao sincronizar dados: {e}")
            QMessageBox.warning(None, "Aviso", f"Erro ao sincronizar dados com o servidor: {e}")
            return False
        finally:
            server_cursor.close()
            cursor.close()

    def execute(self, query, params=()):
        cursor = self.conn.cursor()
        try:
            # Atualizar o timestamp de last_modified para INSERT e UPDATE
            if "INSERT INTO users" in query or "UPDATE users" in query:
                cursor.execute(query, params)
                if "INSERT INTO users" in query:
                    user_id = params[0]  # O ID é o primeiro parâmetro
                    cursor.execute("UPDATE users SET last_modified = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
                elif "UPDATE users" in query:
                    user_id = params[-1]  # O ID é o último parâmetro no UPDATE
                    cursor.execute("UPDATE users SET last_modified = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
            elif "INSERT INTO totp_secrets" in query or "UPDATE totp_secrets" in query:
                cursor.execute(query, params)
                if "INSERT INTO totp_secrets" in query:
                    code_id = params[0]  # O ID é o primeiro parâmetro
                    cursor.execute("UPDATE totp_secrets SET last_modified = CURRENT_TIMESTAMP WHERE id = ?", (code_id,))
                elif "UPDATE totp_secrets" in query:
                    code_id = params[-1]  # O ID é o último parâmetro no UPDATE
                    cursor.execute("UPDATE totp_secrets SET last_modified = CURRENT_TIMESTAMP WHERE id = ?", (code_id,))
            else:
                cursor.execute(query, params)

            self.conn.commit()

            # Sincronizar com o servidor se conectado
            if self.db_type in ["mysql", "postgres"] and self.server_conn:
                success = self.synchronize_data()
                if not success:
                    print("Falha na sincronização após operação de escrita.")
                    QMessageBox.warning(None, "Aviso", "Operação realizada localmente, mas falha ao sincronizar com o servidor. Verifique a conexão e tente novamente.")

            return cursor
        except sqlite3.Error as e:
            print(f"Erro ao executar comando SQL no SQLite: {e}")
            QMessageBox.critical(None, "Erro", f"Erro ao executar comando SQL no SQLite: {e}")
            raise
        except Exception as e:
            print(f"Erro inesperado: {e}")
            QMessageBox.critical(None, "Erro", f"Erro inesperado: {e}")
            raise
        finally:
            cursor.close()

    def fetchall(self, query, params=()):
        cursor = self.conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Erro ao executar consulta no SQLite: {e}")
            QMessageBox.critical(None, "Erro", f"Erro ao executar consulta no SQLite: {e}")
            raise
        finally:
            cursor.close()

    def fetchone(self, query, params=()):
        cursor = self.conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Erro ao executar consulta no SQLite: {e}")
            QMessageBox.critical(None, "Erro", f"Erro ao executar consulta no SQLite: {e}")
            raise
        finally:
            cursor.close()

    def close(self):
        if self.conn:
            self.conn.close()
        if self.server_conn:
            self.server_conn.close()

class ConfigDialog(QDialog):
    def __init__(self, current_config=None):
        super().__init__()
        self.setWindowTitle("Configuração Inicial")
        self.setStyleSheet("""
            QDialog { background-color: #212121; font-family: 'Arial', sans-serif; color: #E0E0E0; }
            QLineEdit { background-color: #424242; border: 1px solid #616161; border-radius: 4px; padding: 8px; font-size: 14px; color: #E0E0E0; }
            QComboBox { background-color: #424242; border: 1px solid #616161; border-radius: 4px; padding: 8px; font-size: 14px; color: #E0E0E0; }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow { image: none; }
            QPushButton { background-color: #0288D1; color: #E0E0E0; border: none; border-radius: 4px; padding: 8px; font-size: 12px; }
            QPushButton:hover { background-color: #0277BD; }
            QLabel { font-size: 14px; color: #E0E0E0; }
        """)
        self.layout = QFormLayout()

        self.db_type = QComboBox()
        self.db_type.addItems(["SQLite", "MySQL", "PostgreSQL"])
        self.layout.addRow("Tipo de Banco de Dados:", self.db_type)

        self.db_host = QLineEdit()
        self.db_user = QLineEdit()
        self.db_password = QLineEdit()
        self.db_password.setEchoMode(QLineEdit.Password)
        self.db_port = QLineEdit()
        self.db_name = QLineEdit()

        self.layout.addRow("Host:", self.db_host)
        self.layout.addRow("Usuário:", self.db_user)
        self.layout.addRow("Senha:", self.db_password)
        self.layout.addRow("Porta:", self.db_port)
        self.layout.addRow("Nome do Banco:", self.db_name)

        self.submit_button = QPushButton("Confirmar")
        self.submit_button.clicked.connect(self.accept)
        self.layout.addWidget(self.submit_button)

        self.setLayout(self.layout)
        self.db_type.currentTextChanged.connect(self.toggle_db_fields)

        if current_config:
            db_type = current_config.get("db_type", "sqlite")
            if db_type == "sqlite":
                self.db_type.setCurrentText("SQLite")
            elif db_type == "mysql":
                self.db_type.setCurrentText("MySQL")
            else:
                self.db_type.setCurrentText("PostgreSQL")

            self.db_host.setText(current_config.get("host", ""))
            self.db_user.setText(current_config.get("user", ""))
            self.db_password.setText(current_config.get("password", ""))
            self.db_port.setText(str(current_config.get("port", 5432 if db_type == "postgres" else 3306)))
            self.db_name.setText(current_config.get("database", "authenticator"))

        self.toggle_db_fields(self.db_type.currentText())

    def toggle_db_fields(self, db_type):
        db_fields = [self.db_host, self.db_user, self.db_password, self.db_port, self.db_name]
        for field in db_fields:
            field.setEnabled(db_type in ["MySQL", "PostgreSQL"])

    def get_config(self):
        if self.db_type.currentText() == "SQLite":
            return {"db_type": "sqlite"}
        else:
            return {
                "db_type": "mysql" if self.db_type.currentText() == "MySQL" else "postgres",
                "host": self.db_host.text(),
                "user": self.db_user.text(),
                "password": self.db_password.text(),
                "port": int(self.db_port.text()) if self.db_port.text().isdigit() else (3306 if self.db_type.currentText() == "MySQL" else 5432),
                "database": self.db_name.text() or "authenticator"
            }

class LoginDialog(QDialog):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Login")
        self.setStyleSheet("""
            QDialog { background-color: #212121; font-family: 'Arial', sans-serif; color: #E0E0E0; }
            QLineEdit { background-color: #424242; border: 1px solid #616161; border-radius: 4px; padding: 8px; font-size: 14px; color: #E0E0E0; }
            QPushButton { background-color: #0288D1; color: #E0E0E0; border: none; border-radius: 4px; padding: 6px 12px; font-size: 12px; }
            QPushButton:hover { background-color: #0277BD; }
            QLabel { font-size: 14px; color: #E0E0E0; }
        """)
        self.layout = QFormLayout()
        self.layout.setSpacing(10)
        self.layout.setContentsMargins(20, 20, 20, 20)

        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)

        self.button_layout = QHBoxLayout()
        self.login_button = QPushButton("Entrar")
        self.change_password_button = QPushButton("Alterar Senha")
        self.cancel_button = QPushButton("Cancelar")

        self.button_layout.addWidget(self.login_button)
        self.button_layout.addWidget(self.change_password_button)
        self.button_layout.addWidget(self.cancel_button)

        self.layout.addRow("Usuário:", self.username)
        self.layout.addRow("Senha:", self.password)
        self.layout.addRow(self.button_layout)

        self.login_button.clicked.connect(self.accept)
        self.change_password_button.clicked.connect(self.change_password)
        self.cancel_button.clicked.connect(self.reject)
        self.setLayout(self.layout)

    def change_password(self):
        username = self.username.text()
        old_password = self.password.text()
        user = self.db.fetchone("SELECT id, password, user_type FROM users WHERE username = ?", (username,))
        if user and bcrypt.checkpw(old_password.encode(), user[1].encode()):
            new_password, ok = QInputDialog.getText(self, "Alterar Senha", "Nova Senha:", QLineEdit.Password)
            if ok and new_password:
                hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
                self.db.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
                QMessageBox.information(self, "Sucesso", "Senha alterada com sucesso!")
        else:
            QMessageBox.warning(self, "Erro", "Usuário ou senha inválidos!")

class UserManagementDialog(QDialog):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Gerenciar Usuários")
        self.setStyleSheet("""
            QDialog { background-color: #212121; font-family: 'Arial', sans-serif; color: #E0E0E0; }
            QTableWidget { background-color: #424242; border: none; color: #E0E0E0; }
            QTableWidget::item { padding: 10px; border-bottom: 1px solid #616161; }
            QHeaderView::section { background-color: #424242; color: #E0E0E0; padding: 5px; border: none; }
            QPushButton { background-color: #0288D1; color: #E0E0E0; border: none; border-radius: 4px; padding: 8px; font-size: 12px; }
            QPushButton#resetButton { background-color: #D32F2F; }
            QPushButton:hover { background-color: #0277BD; }
            QPushButton#resetButton:hover { background-color: #B71C1C; }
        """)
        self.layout = QVBoxLayout()

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Usuário", "Email", "Tipo"])
        self.load_users()

        self.add_button = QPushButton("Adicionar Usuário")
        self.edit_button = QPushButton("Editar Usuário")
        self.delete_button = QPushButton("Excluir Usuário")
        self.reset_password_button = QPushButton("Resetar Senha")
        self.reset_password_button.setObjectName("resetButton")

        self.layout.addWidget(self.table)
        self.layout.addWidget(self.add_button)
        self.layout.addWidget(self.edit_button)
        self.layout.addWidget(self.delete_button)
        self.layout.addWidget(self.reset_password_button)

        self.add_button.clicked.connect(self.add_user)
        self.edit_button.clicked.connect(self.edit_user)
        self.delete_button.clicked.connect(self.delete_user)
        self.reset_password_button.clicked.connect(self.reset_password)
        self.setLayout(self.layout)

    def load_users(self):
        users = self.db.fetchall("SELECT id, username, email, user_type FROM users", ())
        self.table.setRowCount(len(users))
        for row, user in enumerate(users):
            for col, data in enumerate(user):
                self.table.setItem(row, col, QTableWidgetItem(str(data)))

    def add_user(self):
        username, ok1 = QInputDialog.getText(self, "Novo Usuário", "Usuário:")
        if not ok1 or not username:
            return
        email, ok2 = QInputDialog.getText(self, "Novo Usuário", "Email:")
        if not ok2:
            return
        password, ok3 = QInputDialog.getText(self, "Novo Usuário", "Senha:", QLineEdit.Password)
        if not ok3 or not password:
            return
        user_type, ok4 = QInputDialog.getItem(self, "Novo Usuário", "Tipo:", ["admin", "user"], 0, False)
        if not ok4:
            return
        try:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            user_id = str(uuid.uuid4())
            self.db.execute("INSERT INTO users (id, username, email, password, user_type) VALUES (?, ?, ?, ?, ?)",
                            (user_id, username, email, hashed, user_type))
            self.load_users()
            QMessageBox.information(self, "Sucesso", "Usuário adicionado com sucesso!")
        except sqlite3.IntegrityError as e:
            QMessageBox.warning(self, "Erro", f"Erro ao adicionar usuário: {e}\nPossivelmente o nome de usuário já existe.")

    def edit_user(self):
        selected = self.table.currentRow()
        if selected >= 0:
            user_id = self.table.item(selected, 0).text()
            username, ok1 = QInputDialog.getText(self, "Editar Usuário", "Usuário:")
            if not ok1 or not username:
                return
            email, ok2 = QInputDialog.getText(self, "Editar Usuário", "Email:")
            if not ok2:
                return
            user_type, ok3 = QInputDialog.getItem(self, "Editar Usuário", "Tipo:", ["admin", "user"], 0, False)
            if not ok3:
                return
            try:
                self.db.execute("UPDATE users SET username = ?, email = ?, user_type = ? WHERE id = ?",
                                (username, email, user_type, user_id))
                self.load_users()
                QMessageBox.information(self, "Sucesso", "Usuário editado com sucesso!")
            except sqlite3.IntegrityError as e:
                QMessageBox.warning(self, "Erro", f"Erro ao editar usuário: {e}\nPossivelmente o nome de usuário já existe.")
        else:
            QMessageBox.warning(self, "Aviso", "Selecione um usuário para editar.")

    def delete_user(self):
        selected = self.table.currentRow()
        if selected >= 0:
            user_id = self.table.item(selected, 0).text()
            username = self.table.item(selected, 1).text()
            reply = QMessageBox.question(self, "Excluir Usuário",
                                         f"Deseja excluir o usuário '{username}'?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
                self.db.execute("DELETE FROM totp_secrets WHERE user_id = ?", (user_id,))
                self.load_users()
                QMessageBox.information(self, "Sucesso", "Usuário excluído com sucesso!")
        else:
            QMessageBox.warning(self, "Aviso", "Selecione um usuário para excluir.")

    def reset_password(self):
        selected = self.table.currentRow()
        if selected >= 0:
            user_id = self.table.item(selected, 0).text()
            username = self.table.item(selected, 1).text()
            reply = QMessageBox.question(self, "Resetar Senha",
                                         f"Deseja resetar a senha do usuário '{username}' para '123'?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                new_password = "123"
                hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
                self.db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
                QMessageBox.information(self, "Sucesso", f"Senha do usuário '{username}' resetada para '123'.")
        else:
            QMessageBox.warning(self, "Aviso", "Selecione um usuário para resetar a senha.")

class CodeEntry(QWidget):
    def __init__(self, code_id, label, secret, is_default, parent=None):
        super().__init__(parent)
        self.code_id = code_id
        self.secret = secret
        self.is_default = is_default
        self.totp = pyotp.TOTP(secret)

        self.layout = QHBoxLayout()
        self.layout.setContentsMargins(10, 10, 10, 10)

        self.label = QLabel(label)
        self.label.setStyleSheet("font-size: 16px; color: #E0E0E0; font-weight: bold;")

        self.code_label = QLabel(self.totp.now())
        self.code_label.setStyleSheet("font-size: 20px; color: #4FC3F7; font-weight: bold; margin-left: 20px;")

        self.timer_label = QLabel(str(self.totp.interval - (int(datetime.now().timestamp()) % self.totp.interval)))
        self.timer_label.setStyleSheet("""
            font-size: 12px; 
            color: #E0E0E0; 
            background-color: #0288D1; 
            border-radius: 12px; 
            padding: 6px; 
            width: 24px; 
            height: 24px; 
            text-align: center;
        """)

        self.layout.addWidget(self.label)
        self.layout.addStretch()
        self.layout.addWidget(self.code_label)
        self.layout.addStretch()
        self.layout.addWidget(self.timer_label)

        self.setLayout(self.layout)
        self.setStyleSheet("border-bottom: 1px solid #616161;")

    def update(self):
        self.code_label.setText(self.totp.now())
        remaining_time = str(self.totp.interval - (int(datetime.now().timestamp()) % self.totp.interval))
        self.timer_label.setText(remaining_time)

class AuthenticatorApp(QMainWindow):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.user = None
        self.setWindowTitle("Autenticador")
        self.setWindowFlags(Qt.WindowStaysOnTopHint)

        self.setStyleSheet("""
            QMainWindow { background-color: #212121; font-family: 'Arial', sans-serif; color: #E0E0E0; }
            QPushButton#fab { background-color: #0288D1; color: #E0E0E0; border: none; border-radius: 28px; width: 56px; height: 56px; font-size: 24px; }
            QPushButton#fab:hover { background-color: #0277BD; }
            QToolBar { background-color: #212121; border: none; }
            QPushButton { background-color: #424242; color: #E0E0E0; border: none; padding: 5px; }
            QPushButton:hover { background-color: #616161; }
        """)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setAlignment(Qt.AlignTop)

        self.tray_icon = None
        self.setup_tray_icon()

        self.toolbar = self.addToolBar("Ações")
        self.logout_button = QPushButton("Logoff")
        self.logout_button.clicked.connect(self.logout)
        self.logout_button.setStyleSheet("""
            QPushButton { background-color: #D32F2F; color: #E0E0E0; border: none; padding: 5px; font-size: 12px; }
            QPushButton:hover { background-color: #B71C1C; }
        """)

        self.actions_menu = QMenu()

        self.set_default_action = QAction("Definir como Padrão", self)
        self.delete_action = QAction("Excluir Código", self)
        self.manage_users_action = QAction("Gerenciar Usuários", self)
        self.edit_config_action = QAction("Editar Configurações", self)

        self.actions_menu.addAction(self.set_default_action)
        self.actions_menu.addAction(self.delete_action)
        self.actions_menu.addAction(self.manage_users_action)
        self.actions_menu.addAction(self.edit_config_action)

        self.actions_button = QPushButton("⋮")
        self.actions_button.setStyleSheet("font-size: 18px; padding: 10px; border: none;")
        self.actions_button.setMenu(self.actions_menu)

        self.toolbar.addWidget(self.logout_button)
        self.toolbar.addWidget(self.actions_button)

        self.codes_layout = QVBoxLayout()
        self.codes_layout.setAlignment(Qt.AlignTop)
        self.main_layout.addLayout(self.codes_layout)

        fab_layout = QHBoxLayout()
        fab_layout.addStretch()
        self.fab = QPushButton("+")
        self.fab.setObjectName("fab")
        self.fab.clicked.connect(self.add_code)
        fab_layout.addWidget(self.fab)
        self.main_layout.addLayout(fab_layout)

        self.set_default_action.triggered.connect(self.set_default_code)
        self.delete_action.triggered.connect(self.delete_code)
        self.manage_users_action.triggered.connect(self.manage_users)
        self.edit_config_action.triggered.connect(self.edit_config)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_codes)
        self.timer.start(1000)

        self.show_login()

    def logout(self):
        self.user = None
        self.load_codes()
        self.show_login()

    def setup_tray_icon(self):
        def create_icon():
            image = Image.new("RGB", (64, 64), color="#2E2E2E")
            draw = ImageDraw.Draw(image)
            draw.text((10, 20), "TOTP", fill="#FFFFFF")
            return image

        def on_restore(icon):
            icon.stop()
            self.showNormal()
            self.activateWindow()
            self.setup_tray_icon()

        def on_exit(icon):
            icon.stop()
            QApplication.quit()

        def on_copy_code(icon):
            if self.user:
                self.copy_default_code()

        menu = (
            Item("Copiar Código Padrão", lambda icon: on_copy_code(icon)),
            Item("Restaurar", lambda icon: on_restore(icon)),
            Item("Sair", lambda icon: on_exit(icon))
        )
        self.tray_icon = pystray.Icon("Authenticator", icon=create_icon(), title="Autenticador", menu=menu)

        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def closeEvent(self, event):
        self.hide()
        if self.tray_icon:
            self.tray_icon.notify("Aplicativo minimizado para a bandeja do sistema.", "Autenticador")
        event.ignore()

    def show_login(self):
        login_dialog = LoginDialog(self.db)
        if login_dialog.exec_() == QDialog.Accepted:
            username = login_dialog.username.text()
            password = login_dialog.password.text()
            user = self.db.fetchone("SELECT id, password, user_type FROM users WHERE username = ?", (username,))
            if user and bcrypt.checkpw(password.encode(), user[1].encode()):
                self.user = {"id": user[0], "user_type": user[2]}
                self.manage_users_action.setVisible(self.user["user_type"] == "admin")
                self.edit_config_action.setVisible(self.user["user_type"] == "admin")
                self.load_codes()
            else:
                QMessageBox.warning(self, "Erro", "Usuário ou senha inválidos!")
                self.show_login()
        else:
            reply = QMessageBox.question(self, "Sair", "Deseja sair do aplicativo?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                if self.tray_icon:
                    self.tray_icon.stop()
                QApplication.quit()
            else:
                self.show_login()

    def edit_config(self):
        if self.user["user_type"] != "admin":
            QMessageBox.warning(self, "Acesso Negado", "Apenas administradores podem editar as configurações.")
            return

        config_file = "config.json"
        current_config = None
        if os.path.exists(config_file):
            try:
                with open(config_file, 'rb') as f:
                    encrypted_config = f.read()
                current_config = json.loads(CIPHER.decrypt(encrypted_config).decode())
            except Exception as e:
                QMessageBox.warning(self, "Aviso", f"Falha ao carregar configurações atuais: {e}\nAs configurações serão editadas a partir dos valores padrão.")

        config_dialog = ConfigDialog(current_config=current_config)
        if config_dialog.exec_():
            config = config_dialog.get_config()
            encrypted_config = CIPHER.encrypt(json.dumps(config).encode())
            with open(config_file, 'wb') as f:
                f.write(encrypted_config)
            QMessageBox.information(self, "Sucesso", "Configurações salvas com sucesso. Reinicie o aplicativo.")
            if self.tray_icon:
                self.tray_icon.stop()
            QApplication.quit()

    def load_codes(self):
        for i in reversed(range(self.codes_layout.count())):
            widget = self.codes_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        if self.user:
            codes = self.db.fetchall("SELECT id, label, secret, is_default FROM totp_secrets WHERE user_id = ?",
                                     (self.user["id"],))
            for code in codes:
                code_entry = CodeEntry(code[0], code[1], code[2], code[3], self)
                code_entry.mousePressEvent = lambda event, entry=code_entry: self.copy_code(entry)
                self.codes_layout.addWidget(code_entry)
            self.adjustSize()

    def update_codes(self):
        if self.user:
            for i in range(self.codes_layout.count()):
                widget = self.codes_layout.itemAt(i).widget()
                if widget and isinstance(widget, CodeEntry):
                    widget.update()

    def add_code(self):
        label, ok1 = QInputDialog.getText(self, "Novo Código", "Rótulo:")
        if not ok1 or not label:
            return
        secret, ok2 = QInputDialog.getText(self, "Novo Código", "Chave Secreta:")
        if not ok2 or not secret:
            return
        try:
            self.db.execute("INSERT INTO totp_secrets (id, user_id, secret, label, is_default) VALUES (?, ?, ?, ?, ?)",
                            (str(uuid.uuid4()), self.user["id"], secret, label, False))
            self.load_codes()
            QMessageBox.information(self, "Sucesso", "Código TOTP adicionado com sucesso!")
        except Exception as e:
            QMessageBox.warning(self, "Erro", f"Erro ao adicionar código: {e}")

    def set_default_code(self):
        codes = self.db.fetchall("SELECT id, label FROM totp_secrets WHERE user_id = ?", (self.user["id"],))
        if not codes:
            QMessageBox.warning(self, "Aviso", "Nenhum código disponível para definir como padrão.")
            return
        labels = [code[1] for code in codes]
        label, ok = QInputDialog.getItem(self, "Definir como Padrão", "Selecione o código:", labels, 0, False)
        if ok:
            code_id = next(code[0] for code in codes if code[1] == label)
            self.db.execute("UPDATE totp_secrets SET is_default = FALSE WHERE user_id = ?", (self.user["id"],))
            self.db.execute("UPDATE totp_secrets SET is_default = TRUE WHERE id = ?", (code_id,))
            self.load_codes()

    def delete_code(self):
        codes = self.db.fetchall("SELECT id, label FROM totp_secrets WHERE user_id = ?", (self.user["id"],))
        if not codes:
            QMessageBox.warning(self, "Aviso", "Nenhum código disponível para excluir.")
            return
        labels = [code[1] for code in codes]
        label, ok = QInputDialog.getItem(self, "Excluir Código", "Selecione o código:", labels, 0, False)
        if ok:
            code_id = next(code[0] for code in codes if code[1] == label)
            self.db.execute("DELETE FROM totp_secrets WHERE id = ?", (code_id,))
            self.load_codes()

    def copy_code(self, code_entry):
        code = code_entry.code_label.text()
        pyperclip.copy(code)
        if self.tray_icon:
            self.tray_icon.notify("Código copiado para a área de transferência!", "Autenticador")

    def copy_default_code(self):
        default_code = self.db.fetchone("SELECT secret FROM totp_secrets WHERE user_id = ? AND is_default = TRUE",
                                        (self.user["id"],))
        if default_code:
            totp = pyotp.TOTP(default_code[0])
            code = totp.now()
            pyperclip.copy(code)
            if self.tray_icon:
                self.tray_icon.notify("Código padrão copiado para a área de transferência!", "Autenticador")
        else:
            if self.tray_icon:
                self.tray_icon.notify("Nenhum código padrão definido.", "Autenticador")

    def manage_users(self):
        if self.user["user_type"] == "admin":
            dialog = UserManagementDialog(self.db)
            dialog.exec_()

def main():
    app = QApplication(sys.argv)

    config_file = "config.json"
    config = None
    if os.path.exists(config_file):
        try:
            with open(config_file, 'rb') as f:
                encrypted_config = f.read()
            config = json.loads(CIPHER.decrypt(encrypted_config).decode())
        except Exception as e:
            QMessageBox.warning(None, "Aviso", f"Falha ao descriptografar config.json: {e}\nUm novo arquivo de configuração será criado.")
            os.remove(config_file)
            os.remove(KEY_FILE)
            regenerate_encryption_key()

    if not config:
        config_dialog = ConfigDialog()
        if config_dialog.exec_():
            config = config_dialog.get_config()
            encrypted_config = CIPHER.encrypt(json.dumps(config).encode())
            with open(config_file, 'wb') as f:
                f.write(encrypted_config)
        else:
            sys.exit()

    try:
        db = Database(**config)
        admin_user = db.fetchone("SELECT username FROM users WHERE username = ?", ("admin",))
        if not admin_user:
            hashed = bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()
            user_id = str(uuid.uuid4())
            db.execute("INSERT INTO users (id, username, email, password, user_type) VALUES (?, ?, ?, ?, ?)",
                       (user_id, "admin", "admin@example.com", hashed, "admin"))
            user = db.fetchone("SELECT username FROM users WHERE id = ?", (user_id,))
    except (mysql.connector.Error, psycopg2.Error, ValueError, Exception) as err:
        QMessageBox.critical(None, "Erro", f"Falha ao configurar o banco de dados local: {err}")
        sys.exit()

    authenticator = AuthenticatorApp(db)
    authenticator.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()