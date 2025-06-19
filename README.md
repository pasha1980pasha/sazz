from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-GCM Шифровщик/Дешифровщик")
        self.root.geometry("600x700")
        
        self.password_var = tk.StringVar()
        self.file_path = None
        self.encrypted_data = None
        self.mode_var = tk.StringVar(value="text")  # text или file
        
        self.create_widgets()
    
    def create_widgets(self):
        # Режим работы (текст или файл)
        mode_frame = ttk.LabelFrame(self.root, text="Режим")
        mode_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Radiobutton(mode_frame, text="Текст", variable=self.mode_var, value="text").pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text="Файл", variable=self.mode_var, value="file").pack(side="left", padx=5)
        
        # Пароль
        password_frame = ttk.LabelFrame(self.root, text="Пароль")
        password_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(password_frame, text="Введите пароль:").pack(pady=5)
        ttk.Entry(password_frame, textvariable=self.password_var, show="*").pack(pady=5, fill="x", padx=5)
        
        # Текстовые данные (видно в режиме "текст")
        self.data_frame = ttk.LabelFrame(self.root, text="Текст")
        self.data_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        ttk.Label(self.data_frame, text="Введите текст:").pack(pady=5)
        self.data_entry = tk.Text(self.data_frame, height=5)
        self.data_entry.pack(pady=5, fill="both", expand=True, padx=5)
        
        # Файловые данные (видно в режиме "файл")
        self.file_frame = ttk.LabelFrame(self.root, text="Файл")
        
        ttk.Button(self.file_frame, text="Выбрать файл", command=self.select_file).pack(pady=5)
        self.file_label = ttk.Label(self.file_frame, text="Файл не выбран")
        self.file_label.pack(pady=5)
        
        # Кнопки буфера обмена (только для текста)
        self.clipboard_frame = ttk.Frame(self.root)
        
        ttk.Button(
            self.clipboard_frame,
            text="Копировать результат",
            command=self.copy_result,
            width=20
        ).pack(side="left", padx=5)
        
        ttk.Button(
            self.clipboard_frame,
            text="Вставить данные",
            command=self.paste_data,
            width=20
        ).pack(side="right", padx=5)
        
        # Основные кнопки
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10, fill="x", padx=10)
        
        ttk.Button(button_frame, text="Зашифровать", command=self.encrypt).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Дешифровать", command=self.decrypt).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Очистить", command=self.clear).pack(side="right", padx=5)
        
        # Результат
        result_frame = ttk.LabelFrame(self.root, text="Результат")
        result_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.result_text = tk.Text(result_frame, state="disabled")
        self.result_text.pack(pady=5, fill="both", expand=True, padx=5)
        
        # Обновляем видимость элементов в зависимости от режима
        self.mode_var.trace_add("write", self.update_ui)
        self.update_ui()
    
    def update_ui(self, *args):
        mode = self.mode_var.get()
        if mode == "text":
            self.data_frame.pack(pady=10, padx=10, fill="both", expand=True)
            self.file_frame.pack_forget()
            self.clipboard_frame.pack(pady=5, padx=10, fill="x")
        else:
            self.data_frame.pack_forget()
            self.file_frame.pack(pady=10, padx=10, fill="x")
            self.clipboard_frame.pack_forget()
    
    def select_file(self):
        self.file_path = filedialog.askopenfilename(
            title="Выберите файл",
            filetypes=[("Все файлы", "*.*"), 
                      ("Документы Word", "*.docx"), 
                      ("Excel", "*.xlsx"), 
                      ("PDF", "*.pdf")]
        )
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))
    
    def copy_result(self):
        result = self.result_text.get("1.0", "end-1c")
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Успех", "Результат скопирован в буфер!")
    
    def paste_data(self):
        try:
            data = self.root.clipboard_get()
            self.data_entry.delete("1.0", "end")
            self.data_entry.insert("1.0", data)
        except tk.TclError:
            messagebox.showerror("Ошибка", "Буфер обмена пуст!")
    
    def generate_key(self, password: str, salt: bytes = None):
        if salt is None:
            salt = get_random_bytes(16)
        
        key = scrypt(password, salt, key_len=32, N=2**20, r=8, p=1)
        
        with open('key_config.json', 'w') as f:
            json.dump({'salt': salt.hex()}, f)
        
        return key
    
    def load_key(self, password: str):
        try:
            with open('key_config.json') as f:
                config = json.load(f)
                salt = bytes.fromhex(config['salt'])
                return scrypt(password, salt, key_len=32, N=2**20, r=8, p=1)
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return self.generate_key(password)
    
    def encrypt(self):
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль!")
            return
            
        mode = self.mode_var.get()
        
        try:
            if mode == "text":
                data = self.data_entry.get("1.0", "end-1c")
                if not data:
                    messagebox.showerror("Ошибка", "Введите текст для шифрования!")
                    return
                
                key = self.load_key(password)
                cipher = AES.new(key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
                
                self.encrypted_data = {
                    'ciphertext': ciphertext.hex(),
                    'nonce': cipher.nonce.hex(),
                    'tag': tag.hex()
                }
                
                self.show_result(json.dumps(self.encrypted_data, indent=2))
                messagebox.showinfo("Успех", "Текст успешно зашифрован!")
                
            else:  # file mode
                if not self.file_path:
                    messagebox.showerror("Ошибка", "Выберите файл для шифрования!")
                    return
                
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()
                
                key = self.load_key(password)
                cipher = AES.new(key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(file_data)
                
                encrypted_data = {
                    'ciphertext': ciphertext.hex(),
                    'nonce': cipher.nonce.hex(),
                    'tag': tag.hex()
                }
                
                output_path = filedialog.asksaveasfilename(
                    title="Сохранить зашифрованный файл",
                    defaultextension=".enc",
                    filetypes=[("Зашифрованные файлы", "*.enc")]
                )
                
                if output_path:
                    with open(output_path, 'w') as f:
                        json.dump(encrypted_data, f)
                    
                    self.show_result(f"Файл успешно зашифрован и сохранен как:\n{output_path}")
                    messagebox.showinfo("Успех", "Файл успешно зашифрован!")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {str(e)}")
    
    def decrypt(self):
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль!")
            return
            
        mode = self.mode_var.get()
        
        try:
            if mode == "text":
                data = self.data_entry.get("1.0", "end-1c")
                if not data:
                    messagebox.showerror("Ошибка", "Введите данные для дешифрования!")
                    return
                
                encrypted_data = json.loads(data)
                required_fields = {'ciphertext', 'nonce', 'tag'}
                if not all(field in encrypted_data for field in required_fields):
                    raise ValueError("Неверный формат данных! Отсутствуют необходимые поля.")
                
                key = self.load_key(password)
                cipher = AES.new(
                    key,
                    AES.MODE_GCM,
                    nonce=bytes.fromhex(encrypted_data['nonce'])
                )
                
                decrypted = cipher.decrypt_and_verify(
                    bytes.fromhex(encrypted_data['ciphertext']),
                    bytes.fromhex(encrypted_data['tag'])
                )
                
                self.show_result(decrypted.decode('utf-8'))
                messagebox.showinfo("Успех", "Текст успешно дешифрован!")
                
            else:  # file mode
                if not self.file_path:
                    messagebox.showerror("Ошибка", "Выберите файл для дешифрования!")
                    return
                
                with open(self.file_path, 'r') as f:
                    encrypted_data = json.load(f)
                
                required_fields = {'ciphertext', 'nonce', 'tag'}
                if not all(field in encrypted_data for field in required_fields):
                    raise ValueError("Неверный формат файла! Отсутствуют необходимые поля.")
                
                key = self.load_key(password)
                cipher = AES.new(
                    key,
                    AES.MODE_GCM,
                    nonce=bytes.fromhex(encrypted_data['nonce'])
                )
                
                decrypted = cipher.decrypt_and_verify(
                    bytes.fromhex(encrypted_data['ciphertext']),
                    bytes.fromhex(encrypted_data['tag'])
                )
                
                output_path = filedialog.asksaveasfilename(
                    title="Сохранить дешифрованный файл",
                    filetypes=[("Документы Word", "*.docx"), 
                              ("Excel", "*.xlsx"), 
                              ("PDF", "*.pdf"),
                              ("Все файлы", "*.*")]
                )
                
                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(decrypted)
                    
                    self.show_result(f"Файл успешно дешифрован и сохранен как:\n{output_path}")
                    messagebox.showinfo("Успех", "Файл успешно дешифрован!")
        
        except json.JSONDecodeError:
            messagebox.showerror("Ошибка", "Неверный формат данных! Ожидается JSON с полями ciphertext, nonce и tag.")
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Ошибка дешифрования: {str(e)}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Неизвестная ошибка: {str(e)}")
    
    def show_result(self, text):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.config(state="disabled")
    
    def clear(self):
        self.password_var.set("")
        self.data_entry.delete("1.0", "end")
        self.file_path = None
        self.file_label.config(text="Файл не выбран")
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.config(state="disabled")
        self.encrypted_data = None

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
