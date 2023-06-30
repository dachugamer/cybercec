import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QMenuBar, QAction, QFileDialog
from PyQt5.QtGui import QIcon
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import re
import hashlib

class App(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        
        self.input_text = QTextEdit()
        layout.addWidget(QLabel('Ingresa tu contraseña:'))
        layout.addWidget(self.input_text)

        self.name_text = QTextEdit()
        layout.addWidget(QLabel('Nombre o enlace:'))
        layout.addWidget(self.name_text)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(QLabel('Resultado:'))
        layout.addWidget(self.result_text)

        self.encrypt_button = QPushButton('Encriptar', self)
        self.encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton('Desencriptar', self)
        self.decrypt_button.clicked.connect(self.decrypt)
        layout.addWidget(self.decrypt_button)

        self.verify_button = QPushButton('Verificar seguridad', self)
        self.verify_button.clicked.connect(self.verify)
        layout.addWidget(self.verify_button)

        self.save_button = QPushButton('Guardar', self)
        self.save_button.clicked.connect(self.save)
        layout.addWidget(self.save_button)

        self.setLayout(layout)
        self.setGeometry(300, 300, 300, 300)
        self.setWindowTitle('Contraseña segura')

        self.create_menu()
# Configurar el icono de la aplicación
        icon = QIcon("C:/Users/danid/Downloads/program32.jpg")
        self.setWindowIcon(icon)
    def create_menu(self):
        menubar = QMenuBar(self)

        # Menú Programa
        programa_menu = menubar.addMenu('Programa')

        # Menú Configuración
        configuracion_menu = menubar.addMenu('Configuración')
        archivo_action = QAction('Seleccionar archivo de texto', self)
        archivo_action.triggered.connect(self.select_file)
        configuracion_menu.addAction(archivo_action)

        self.layout().setMenuBar(menubar)

    def select_file(self):
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getSaveFileName(self, 'Seleccionar archivo de texto', '', 'Archivos de texto (*.txt)')
        if file_path:
            self.archivo = file_path

    def encrypt(self):
        text = self.input_text.toPlainText()
        encrypted = self.encriptar(text, self.clave)
        self.result_text.setPlainText(encrypted)

    def decrypt(self):
        text = self.input_text.toPlainText()
        try:
            decrypted = self.desencriptar(text, self.clave)
            self.result_text.setPlainText(decrypted)
        except:
            self.result_text.setPlainText('No se pudo desencriptar. Asegúrate de que la entrada sea una contraseña encriptada.')

    def verify(self):
        text = self.input_text.toPlainText()
        result = self.verificar_seguridad(text)
        self.result_text.setPlainText(result)

    def save(self):
        name = self.name_text.toPlainText()
        password = self.input_text.toPlainText()
        encrypted_password = self.encriptar(password, self.clave)
        entry = f"WEB:{name}=CONTRASEÑA:{encrypted_password}\n"
        with open(self.archivo, 'a') as file:
            file.write(entry)
        self.name_text.clear()
        self.input_text.clear()
        self.result_text.setPlainText('Guardado en archivo.')

    def verificar_seguridad(self, contrasena):
        if len(contrasena) < 8:
            return 'La contraseña es demasiado corta'
        elif not re.search("[a-z]", contrasena):
            return 'La contraseña no tiene letras minúsculas'
        elif not re.search("[A-Z]", contrasena):
            return 'La contraseña no tiene letras mayúsculas'
        elif not re.search("[0-9]", contrasena):
            return 'La contraseña no tiene números'
        elif not re.search("[_@$]", contrasena):
            return 'La contraseña no tiene caracteres especiales'
        elif re.search("\s", contrasena):
            return 'La contraseña tiene espacios'
        else:
            return 'La contraseña es segura'

    def encriptar(self, contrasena, clave):
        cipher = AES.new(clave, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(contrasena.encode(), AES.block_size))
        return encrypted.hex()

    def desencriptar(self, contrasena_encriptada, clave):
        cipher = AES.new(clave, AES.MODE_ECB)
        decrypted = cipher.decrypt(bytes.fromhex(contrasena_encriptada))
        return unpad(decrypted, AES.block_size).decode()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    clave = hashlib.sha256("una clave secreta".encode()).digest()
    ex.clave = clave
    ex.archivo = 'contraseñas.txt'  # Nombre del archivo de texto
    ex.show()
    sys.exit(app.exec_())
