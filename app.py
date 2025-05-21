import sys
import sqlite3
import mysql.connector
import pyotp
import bcrypt
import pyperclip
import json
import os
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

class Database:
    def __init__(self, db_type, **kwargs):
        self.db_type = db_type
        self.conn = None
        if db_type == "sqlite":
            self.conn = sqlite3.connect(kwargs.get("db_path", "authenticator.db"))
        elif db_type == "mysql":
            host = kwargs.get("host")
            user = kwargs.get("user")
            password = kwargs.get("password")
            port = kwargs.get("port", 3306)
            if not all([host, user, password]):
                raise ValueError("Host, usuário e senha são obrigatórios para MySQL")

            try:
                temp_conn = mysql.connector.connect(
                    host=host,
                    user=user,
                    password=password,
                    port=port
                )
            except mysql.connector.Error as err:
                raise mysql.connector.Error(f"Erro ao conectar ao servidor MySQL: {err}")

            try:
                cursor = temp_conn.cursor()
                cursor.execute("CREATE DATABASE IF NOT EXISTS `authenticator`")
                temp_conn.commit()
            except mysql.connector.Error as err:
                raise mysql.connector.Error(f"Erro ao criar o banco de dados: {err}")
            finally:
                cursor.close()
                temp_conn.close()

            try:
                self.conn = mysql.connector.connect(
                    host=host,
                    user=user,
                    password=password,
                    port=port,
                    database="authenticator"
                )
            except mysql.connector.Error as err:
                raise mysql.connector.Error(f"Erro ao conectar ao banco de dados 'authenticator': {err}")
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        if self.db_type == "sqlite":
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                                                   id TEXT PRIMARY KEY,
                                                                   username TEXT UNIQUE,
                                                                   email TEXT,
                                                                   password TEXT,
                                                                   user_type TEXT
                              )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS totp_secrets (
                                                                          id TEXT PRIMARY KEY,
                                                                          user_id TEXT,
                                                                          secret TEXT,
                                                                          label TEXT,
                                                                          is_default BOOLEAN,
                                                                          FOREIGN KEY (user_id) REFERENCES users(id)
                )''')
        elif self.db_type == "mysql":
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                                                   id VARCHAR(36) PRIMARY KEY,
                username VARCHAR(255) UNIQUE,
                email VARCHAR(255),
                password VARCHAR(255),
                user_type ENUM('admin', 'user')
                )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS totp_secrets (
                                                                          id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36),
                secret VARCHAR(255),
                label VARCHAR(255),
                is_default TINYINT(1),
                FOREIGN KEY (user_id) REFERENCES users(id)
                )''')
        self.conn.commit()

    def execute(self, query, params=()):
        cursor = self.conn.cursor()
        try:
            if self.db_type == "sqlite":
                cursor.execute(query, params)
            elif self.db_type == "mysql":
                mysql_query = query.replace('?', '%s')
                cursor.execute(mysql_query, params)
            self.conn.commit()
            return cursor
        except Exception as e:
            raise Exception(f"Erro ao executar comando SQL: {e}")
        finally:
            cursor.close()

    def fetchall(self, query, params=()):
        cursor = self.conn.cursor()
        try:
            if self.db_type == "sqlite":
                cursor.execute(query, params)
            elif self.db_type == "mysql":
                mysql_query = query.replace('?', '%s')
                cursor.execute(mysql_query, params)
            return cursor.fetchall()
        finally:
            cursor.close()

    def fetchone(self, query, params=()):
        cursor = self.conn.cursor()
        try:
            if self.db_type == "sqlite":
                cursor.execute(query, params)
            elif self.db_type == "mysql":
                mysql_query = query.replace('?', '%s')
                cursor.execute(mysql_query, params)
            return cursor.fetchone()
        finally:
            cursor.close()

class ConfigDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Configuração Inicial")
        self.setStyleSheet("""
            QDialog {
                background-color: #212121;
                font-family: 'Arial', sans-serif;
                color: #E0E0E0;
            }
            QLineEdit {
                background-color: #424242;
                border: 1px solid #616161;
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
                color: #E0E0E0;
            }
            QComboBox {
                background-color: #424242;
                border: 1px solid #616161;
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
                color: #E0E0E0;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
            }
            QPushButton {
                background-color: #0288D1;
                color: #E0E0E0;
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #0277BD;
            }
            QLabel {
                font-size: 14px;
                color: #E0E0E0;
            }
        """)
        self.layout = QFormLayout()

        self.db_type = QComboBox()
        self.db_type.addItems(["SQLite", "MySQL"])
        self.layout.addRow("Tipo de Banco de Dados:", self.db_type)

        self.mysql_host = QLineEdit()
        self.mysql_user = QLineEdit()
        self.mysql_password = QLineEdit()
        self.mysql_password.setEchoMode(QLineEdit.Password)
        self.mysql_port = QLineEdit()
        self.mysql_port.setText("3306")

        self.layout.addRow("MySQL Host:", self.mysql_host)
        self.layout.addRow("MySQL User:", self.mysql_user)
        self.layout.addRow("MySQL Password:", self.mysql_password)
        self.layout.addRow("MySQL Port:", self.mysql_port)

        self.submit_button = QPushButton("Confirmar")
        self.submit_button.clicked.connect(self.accept)
        self.layout.addWidget(self.submit_button)

        self.setLayout(self.layout)
        self.db_type.currentTextChanged.connect(self.toggle_mysql_fields)
        self.toggle_mysql_fields(self.db_type.currentText())

    def toggle_mysql_fields(self, db_type):
        mysql_fields = [self.mysql_host, self.mysql_user, self.mysql_password, self.mysql_port]
        for field in mysql_fields:
            field.setEnabled(db_type == "MySQL")

    def get_config(self):
        if self.db_type.currentText() == "SQLite":
            return {"db_type": "sqlite", "db_path": "authenticator.db"}
        else:
            return {
                "db_type": "mysql",
                "host": self.mysql_host.text(),
                "user": self.mysql_user.text(),
                "password": self.mysql_password.text(),
                "port": int(self.mysql_port.text()) if self.mysql_port.text().isdigit() else 3306
            }

class LoginDialog(QDialog):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Login")
        self.setStyleSheet("""
            QDialog {
                background-color: #212121;
                font-family: 'Arial', sans-serif;
                color: #E0E0E0;
            }
            QLineEdit {
                background-color: #424242;
                border: 1px solid #616161;
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
                color: #E0E0E0;
            }
            QPushButton {
                background-color: #0288D1;
                color: #E0E0E0;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #0277BD;
            }
            QLabel {
                font-size: 14px;
                color: #E0E0E0;
            }
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
            QDialog {
                background-color: #212121;
                font-family: 'Arial', sans-serif;
                color: #E0E0E0;
            }
            QTableWidget {
                background-color: #424242;
                border: none;
                color: #E0E0E0;
            }
            QTableWidget::item {
                padding: 10px;
                border-bottom: 1px solid #616161;
            }
            QHeaderView::section {
                background-color: #424242;
                color: #E0E0E0;
                padding: 5px;
                border: none;
            }
            QPushButton {
                background-color: #0288D1;
                color: #E0E0E0;
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-size: 12px;
            }
            QPushButton#resetButton {
                background-color: #D32F2F;
            }
            QPushButton:hover {
                background-color: #0277BD;
            }
            QPushButton#resetButton:hover {
                background-color: #B71C1C;
            }
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
        users = self.db.fetchall("SELECT id, username, email, user_type FROM users")
        self.table.setRowCount(len(users))
        for row, user in enumerate(users):
            for col, data in enumerate(user):
                self.table.setItem(row, col, QTableWidgetItem(str(data)))

    def add_user(self):
        username, _ = QInputDialog.getText(self, "Novo Usuário", "Usuário:")
        email, _ = QInputDialog.getText(self, "Novo Usuário", "Email:")
        password, _ = QInputDialog.getText(self, "Novo Usuário", "Senha:", QLineEdit.Password)
        user_type, _ = QInputDialog.getItem(self, "Novo Usuário", "Tipo:", ["admin", "user"], 0, False)
        if username and password:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            self.db.execute("INSERT INTO users (id, username, email, password, user_type) VALUES (?, ?, ?, ?, ?)",
                            (str(uuid.uuid4()), username, email, hashed, user_type))
            self.load_users()

    def edit_user(self):
        selected = self.table.currentRow()
        if selected >= 0:
            user_id = self.table.item(selected, 0).text()
            username, _ = QInputDialog.getText(self, "Editar Usuário", "Usuário:")
            email, _ = QInputDialog.getText(self, "Editar Usuário", "Email:")
            user_type, _ = QInputDialog.getItem(self, "Editar Usuário", "Tipo:", ["admin", "user"], 0, False)
            if username:
                self.db.execute("UPDATE users SET username = ?, email = ?, user_type = ? WHERE id = ?",
                                (username, email, user_type, user_id))
                self.load_users()

    def delete_user(self):
        selected = self.table.currentRow()
        if selected >= 0:
            user_id = self.table.item(selected, 0).text()
            self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            self.db.execute("DELETE FROM totp_secrets WHERE user_id = ?", (user_id,))
            self.load_users()

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
            QMainWindow {
                background-color: #212121;
                font-family: 'Arial', sans-serif;
                color: #E0E0E0;
            }
            QPushButton#fab {
                background-color: #0288D1;
                color: #E0E0E0;
                border: none;
                border-radius: 28px;
                width: 56px;
                height: 56px;
                font-size: 24px;
            }
            QPushButton#fab:hover {
                background-color: #0277BD;
            }
            QToolBar {
                background-color: #212121;
                border: none;
            }
            QPushButton {
                background-color: #424242;
                color: #E0E0E0;
                border: none;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #616161;
            }
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
            QPushButton {
                background-color: #D32F2F;
                color: #E0E0E0;
                border: none;
                padding: 5px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #B71C1C;
            }
        """)

        self.actions_menu = QMenu()

        self.set_default_action = QAction("Definir como Padrão", self)
        self.delete_action = QAction("Excluir Código", self)
        self.manage_users_action = QAction("Gerenciar Usuários", self)

        self.actions_menu.addAction(self.set_default_action)
        self.actions_menu.addAction(self.delete_action)
        self.actions_menu.addAction(self.manage_users_action)

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

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_codes)
        self.timer.start(1000)

        self.show_login()

    def logout(self):
        self.user = None
        self.load_codes()  # Limpa a exibição dos códigos
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
        self.tray_icon = pystray.Icon("Authenticator", icon=create_icon(), title="Authenticator", menu=menu)

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
            self.adjustSize()  # Ajusta o tamanho da janela com base no conteúdo

    def update_codes(self):
        if self.user:
            for i in range(self.codes_layout.count()):
                widget = self.codes_layout.itemAt(i).widget()
                if widget and isinstance(widget, CodeEntry):
                    widget.update()

    def add_code(self):
        label, _ = QInputDialog.getText(self, "Novo Código", "Rótulo:")
        secret, _ = QInputDialog.getText(self, "Novo Código", "Chave Secreta:")
        if label and secret:
            self.db.execute("INSERT INTO totp_secrets (id, user_id, secret, label, is_default) VALUES (?, ?, ?, ?, ?)",
                            (str(uuid.uuid4()), self.user["id"], secret, label, False))
            self.load_codes()

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
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config_dialog = ConfigDialog()
        if config_dialog.exec_():
            config = config_dialog.get_config()
            with open(config_file, 'w') as f:
                json.dump(config, f)
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
    except (mysql.connector.Error, ValueError, Exception) as err:
        QMessageBox.critical(None, "Erro", f"Falha ao conectar ou configurar o MySQL: {err}")
        sys.exit()

    authenticator = AuthenticatorApp(db)
    authenticator.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()