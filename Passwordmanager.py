import sys
import json
import string
import random
import hashlib
import os
from cryptography.fernet import Fernet
from PyQt5.QtCore import QSize
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QDialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import itertools


def xor_crypt_string(data, key):
    return ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(data, itertools.cycle(key)))

FIXED_KEY = "3x4mpl3_k3y"

class PasswordManager(QWidget):
    
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Simple Password Manager')
        
        font = QFont("Times New Roman", 18)  # Set the font family and size

        self.website_label = QLabel('Website', self)
        self.website_label.setFont(font)  # Set font for QLabel
        self.website_input = QLineEdit(self)
        self.website_input.setFont(font)  # Set font for QLineEdit
        self.website_input.setFixedSize(QSize(200, 30))

        self.email_label = QLabel('Email', self)
        self.email_label.setFont(font)  # Set font for QLabel
        self.email_input = QLineEdit(self)
        self.email_input.setFont(font)  # Set font for QLineEdit
        self.email_input.setFixedWidth(200)
        self.email_input.setFixedHeight(30)

        self.password_label = QLabel('Password', self)
        self.password_label.setFont(font)  # Set font for QLabel
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFont(font)  # Set font for QLineEdit
        self.password_input.setFixedSize(QSize(200, 30))
        

        self.generate_password_button = QPushButton('Generate Password', self)
        self.generate_password_button.clicked.connect(self.generate_password)

        self.save_password_button = QPushButton('Save Password', self)
        self.save_password_button.clicked.connect(self.save_password)

        self.data_table = QTableWidget(self)
        self.website_label.setFont(font)
        self.data_table.setColumnCount(3)
        self.data_table.setHorizontalHeaderLabels(['Website', 'Email', 'Password'])
        self.data_table.setMinimumSize(600, 400)  # Set minimum size
        self.load_data()

        input_vbox = QVBoxLayout()
        input_vbox.addWidget(self.website_label)
        input_vbox.addWidget(self.website_input)
        input_vbox.addWidget(self.email_label)
        input_vbox.addWidget(self.email_input)
        input_vbox.addWidget(self.password_label)
        input_vbox.addWidget(self.password_input)
        input_vbox.addWidget(self.generate_password_button)
        input_vbox.addWidget(self.save_password_button)

        main_hbox = QHBoxLayout()
        main_hbox.addLayout(input_vbox)
        main_hbox.addWidget(self.data_table)

        self.setLayout(main_hbox)


    def generate_password(self):
        random.seed()
        letters = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        lower_case= list('abcdefghijklmnopqrstuvwxyz')
        numbers = list('0123456789')
        symbols = list('!()-')

    # Combine all the characters into a single list
        characters = letters + lower_case + numbers + symbols

    # Generate a password using random.choice from the characters list
        password = ''.join(random.choice(characters) for _ in range(12))

    # Print the generated password and the characters list
        print("Generated password:", password)
        print("Characters list:", characters)

        self.password_input.setText(password)
        
        
    def save_password(self):
        website = self.website_input.text()
        email = self.email_input.text()
        password = self.password_input.text()

        encrypted_password = xor_crypt_string(password, FIXED_KEY)

        data = {
            'website': website,
            'email': email,
            'password': encrypted_password
        }

        if os.path.exists('data.json'):
            with open('data.json', 'r') as f:
                file_content = f.read()
            stored_data = json.loads(file_content) if file_content else []
        else:
            stored_data = []

        stored_data.append(data)

        with open('data.json', 'w') as f:
            json.dump(stored_data, f, indent=4)

        self.website_input.clear()
        self.email_input.clear()
       
        self.load_data()

    def load_data(self):
        try:
            with open('data.json', 'r') as f:
                file_content = f.read()
                if file_content:
                    stored_data = json.loads(file_content)


                    self.data_table.setRowCount(len(stored_data))

                    for row, data in enumerate(stored_data):
                        for col, key in enumerate(data.keys()):
                            value = data[key]
                            if key == 'password':
                                value = xor_crypt_string(value, FIXED_KEY)
                            item = QTableWidgetItem(value)
                            self.data_table.setItem(row, col, item)


                # Adjust row heights and column widths
                    self.data_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
                    self.data_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
                    self.data_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

                    for row in range(self.data_table.rowCount()):
                        self.data_table.setRowHeight(row, 30)

        except FileNotFoundError:
            pass


class MasterPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Enter Master Password")

        self.password_label = QLabel("Master Password", self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)

        self.submit_button = QPushButton("Submit", self)
        self.submit_button.clicked.connect(self.check_password)

        vbox = QVBoxLayout()
        vbox.addWidget(self.password_label)
        vbox.addWidget(self.password_input)
        vbox.addWidget(self.submit_button)

        self.setLayout(vbox)

    @staticmethod
    def check_master_password(password):
        with open("master_password.txt", "r") as file:
            correct_password = file.read().strip()
            entered_password = hashlib.sha256(password.encode()).hexdigest()
            return entered_password == correct_password

    def check_password(self):
        password = self.password_input.text()
        if self.check_master_password(password):
            self.accept()
            return password
        else:
            self.password_input.clear()
            self.password_input.setPlaceholderText("Incorrect password. Try again.")


class CreateMasterPassword(QDialog):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Create Master Password")

        self.password_label = QLabel("Enter Master Password:", self)
        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.Password)

        self.confirm_password_label = QLabel("Confirm Master Password:", self)
        self.confirm_password_entry = QLineEdit(self)
        self.confirm_password_entry.setEchoMode(QLineEdit.Password)

        self.submit_button = QPushButton("Submit", self)
        self.submit_button.clicked.connect(self.create_password)

        vbox = QVBoxLayout()
        vbox.addWidget(self.password_label)
        vbox.addWidget(self.password_entry)
        vbox.addWidget(self.confirm_password_label)
        vbox.addWidget(self.confirm_password_entry)
        vbox.addWidget(self.submit_button)

        self.setLayout(vbox)

    def create_password(self):
        entered_password = self.password_entry.text()
        confirmed_password = self.confirm_password_entry.text()

        if entered_password == confirmed_password:
            with open("master_password.txt", "w") as f:
                f.write(hashlib.sha256(entered_password.encode()).hexdigest())
            self.accept()
        else:
            error_label = QLabel("Passwords do not match. Try again.")
            self.layout().addWidget(error_label)

def password_check():
    if os.path.exists("master_password.txt"):
        master_password_dialog = MasterPasswordDialog()
        return master_password_dialog.exec_() == QDialog.Accepted
    else:
        create_master_password_dialog = CreateMasterPassword()
        create_master_password_dialog.exec_()
        return password_check()

if __name__ == '__main__':
    app = QApplication(sys.argv)

    if password_check():
        password_manager = PasswordManager()
        password_manager.show()
        sys.exit(app.exec_())

