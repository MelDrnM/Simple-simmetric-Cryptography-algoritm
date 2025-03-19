import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Función para generar una clave
def generar_clave():
    return os.urandom(32)

# Función para cifrar datos
def cifrar_datos(texto, clave):
    iv = os.urandom(16)  # Vector de inicialización de 16 bytes
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Relleno del texto para que sea múltiplo de 16 bytes
    texto_bytes = texto.encode()
    padding_length = 16 - (len(texto_bytes) % 16)
    texto_bytes += bytes([padding_length]) * padding_length

    texto_cifrado = encryptor.update(texto_bytes) + encryptor.finalize()
    return base64.b64encode(iv + texto_cifrado).decode()

# Función para descifrar datos
def descifrar_datos(texto_cifrado, clave):
    texto_cifrado_bytes = base64.b64decode(texto_cifrado)
    iv = texto_cifrado_bytes[:16]
    texto_cifrado_bytes = texto_cifrado_bytes[16:]

    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    texto_descifrado_bytes = decryptor.update(texto_cifrado_bytes) + decryptor.finalize()

    # Eliminar el padding
    padding_length = texto_descifrado_bytes[-1]
    texto_descifrado_bytes = texto_descifrado_bytes[:-padding_length]

    return texto_descifrado_bytes.decode()

# Interfaz
def interfaz():
    clave = generar_clave()

    def cifrar_texto():
        texto = entrada_texto.get("1.0", tk.END).strip()
        longitud_texto= len(texto)
        if longitud_texto != 500:
            messagebox.showerror("Error", f"El texto debe tener exactamente 500 caracteres y tiene {longitud_texto}.")
            return
        texto_cifrado = cifrar_datos(texto, clave)
        salida_texto.delete("1.0", tk.END)
        salida_texto.insert(tk.END, texto_cifrado)

    def descifrar_texto():
        texto_cifrado = entrada_texto.get("1.0", tk.END).strip()
        try:
            texto_descifrado = descifrar_datos(texto_cifrado, clave)
            salida_texto.delete("1.0", tk.END)
            salida_texto.insert(tk.END, texto_descifrado)
        except Exception as e:
            messagebox.showerror("Error", "No se pudo descifrar el mensaje. Verifica la clave y el texto ingresado.")

    ventana = tk.Tk()
    ventana.title("Cifrado con Llave Sincrónica")

    tk.Label(ventana, text="Ingrese texto (500 caracteres):").pack()
    entrada_texto = tk.Text(ventana, height=10, width=60)
    entrada_texto.pack()

    tk.Button(ventana, text="Cifrar", command=cifrar_texto).pack()
    tk.Button(ventana, text="Descifrar", command=descifrar_texto).pack()

    tk.Label(ventana, text="Resultado:").pack()
    salida_texto = tk.Text(ventana, height=10, width=60)
    salida_texto.pack()

    ventana.mainloop()

if __name__ == "__main__":
    interfaz()