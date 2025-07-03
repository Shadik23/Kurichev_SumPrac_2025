import random
import math
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# ================== Вспомогательные функции ==================
def simple_is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def miller_rabin_is_prime(n, k=20):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=64):
    while True:
        num = random.getrandbits(bits)
        if num % 2 == 0:
            num += 1
        if miller_rabin_is_prime(num):
            return num

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modular_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Обратный элемент для a={a} mod {m} не существует")
    else:
        return x % m

def find_primitive_root(p):
    if p == 2:
        return 1
        
    factors = []
    phi = p - 1
    n = phi
    f = 2
    while f * f <= n:
        if n % f == 0:
            factors.append(f)
            while n % f == 0:
                n //= f
        f += 1
    if n > 1:
        factors.append(n)
    
    for g in range(2, p):
        if all(pow(g, phi // factor, p) != 1 for factor in factors):
            return g
    return None

def generate_aes_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()

def encrypt_message(message, key):
    message_bytes = message.encode('utf-8')
    key_stream = (key * ((len(message_bytes) // len(key)) + 1))[:len(message_bytes)]
    return bytes([m ^ k for m, k in zip(message_bytes, key_stream)]).hex()

def decrypt_message(encrypted_hex, key):
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        key_stream = (key * ((len(encrypted_bytes) // len(key)) + 1))[:len(encrypted_bytes)]
        return bytes([e ^ k for e, k in zip(encrypted_bytes, key_stream)]).decode('utf-8', errors='ignore')
    except ValueError:
        raise ValueError("Неверный hex-формат сообщения")

# ================== RSA Функции ==================
def generate_rsa_keys(p, q, e=None):
    if not (simple_is_prime(p) and simple_is_prime(q)):
        raise ValueError("p и q должны быть простыми числами")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    if e is None:
        for e in range(3, phi, 2):
            if math.gcd(e, phi) == 1:
                break
        else:
            raise ValueError(f"Не удалось найти e для φ(n)={phi}")
    elif math.gcd(e, phi) != 1:
        raise ValueError(f"e={e} должно быть взаимно простым с φ(n)={phi}")
    
    d = modular_inverse(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(message, public_key):
    e, n = public_key
    if message < 0 or message >= n:
        raise ValueError(f"Сообщение должно быть в диапазоне [0, {n-1}]")
    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

# ================== GUI Приложение ==================
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Криптографические алгоритмы")
        self.root.geometry("800x600")
        
        # Состояние Диффи-Хеллмана
        self.dh_p = None
        self.dh_g = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.dh_shared_secret = None
        
        self.setup_ui()
    
    def setup_ui(self):
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(self.main_frame, text="Выберите алгоритм:", font=('Arial', 14)).pack(pady=10)
        
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(pady=20)
        
        self.rsa_btn = ttk.Button(btn_frame, text="RSA", command=self.show_rsa_interface, width=20)
        self.rsa_btn.pack(side=tk.LEFT, padx=10)
        
        self.dh_btn = ttk.Button(btn_frame, text="Диффи-Хеллман", command=self.show_dh_interface, width=20)
        self.dh_btn.pack(side=tk.LEFT, padx=10)
        
        self.output_area = scrolledtext.ScrolledText(self.main_frame, height=20, wrap=tk.WORD)
        self.output_area.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Контекстное меню для области вывода
        self.output_menu = tk.Menu(self.output_area, tearoff=0)
        self.output_menu.add_command(label="Копировать", command=self.copy_output_text)
        self.output_area.bind("<Button-3>", self.show_output_menu)
        
        self.init_rsa_interface()
        self.init_dh_interface()
        self.hide_all_interfaces()
    
    def create_entry_menu(self, widget):
        """Создает контекстное меню для поля ввода"""
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Вставить", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_command(label="Копировать", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Вырезать", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_separator()
        menu.add_command(label="Выделить все", command=lambda: widget.select_range(0, tk.END))
        return menu
    
    def show_entry_menu(self, event):
        """Показывает контекстное меню для поля ввода"""
        widget = event.widget
        menu = self.create_entry_menu(widget)
        menu.tk_popup(event.x_root, event.y_root)
    
    def show_output_menu(self, event):
        """Показывает контекстное меню для области вывода"""
        self.output_menu.tk_popup(event.x_root, event.y_root)
    
    def copy_output_text(self):
        """Копирует текст из области вывода в буфер обмена"""
        if self.output_area.tag_ranges("sel"):
            selected_text = self.output_area.get("sel.first", "sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        else:
            all_text = self.output_area.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(all_text)
    
    def show_context_menu(self, event):
        self.context_menu.tk_popup(event.x_root, event.y_root)
    
    def copy_text(self):
        # Если есть выделенный текст - копируем его, иначе весь текст
        if self.output_area.tag_ranges("sel"):
            selected_text = self.output_area.get("sel.first", "sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        else:
            all_text = self.output_area.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(all_text)
    
    def hide_all_interfaces(self):
        if hasattr(self, 'rsa_frame'):
            self.rsa_frame.pack_forget()
        if hasattr(self, 'dh_frame'):
            self.dh_frame.pack_forget()
    
    def clear_output(self):
        self.output_area.delete(1.0, tk.END)
    
    def print_output(self, text):
        self.output_area.insert(tk.END, text + "\n")
        self.output_area.see(tk.END)
    
    def show_main_interface(self):
        self.hide_all_interfaces()
        self.clear_output()
    
    # ========== RSA Интерфейс ==========
    def init_rsa_interface(self):
        self.rsa_frame = ttk.Frame(self.main_frame)
        
        input_frame = ttk.Frame(self.rsa_frame)
        input_frame.pack(pady=10)
        
        ttk.Label(input_frame, text="p:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.rsa_p_entry = ttk.Entry(input_frame)
        self.rsa_p_entry.grid(row=0, column=1, padx=5, pady=5)
        self.rsa_p_entry.bind("<Button-3>", self.show_entry_menu)  # Привязка контекстного меню
        
        ttk.Label(input_frame, text="q:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.rsa_q_entry = ttk.Entry(input_frame)
        self.rsa_q_entry.grid(row=1, column=1, padx=5, pady=5)
        self.rsa_q_entry.bind("<Button-3>", self.show_entry_menu)  # Привязка контекстного меню
        
        ttk.Label(input_frame, text="Сообщение:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.rsa_msg_entry = ttk.Entry(input_frame)
        self.rsa_msg_entry.grid(row=2, column=1, padx=5, pady=5)
        self.rsa_msg_entry.bind("<Button-3>", self.show_entry_menu)  # Привязка контекстного меню
        
        btn_frame = ttk.Frame(self.rsa_frame)
        btn_frame.pack(pady=10)
        
        self.rsa_generate_btn = ttk.Button(btn_frame, text="Сгенерировать простые", command=self.generate_primes)
        self.rsa_generate_btn.pack(side=tk.LEFT, padx=5)
        
        self.rsa_encrypt_btn = ttk.Button(btn_frame, text="Зашифровать", command=self.encrypt_rsa)
        self.rsa_encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.rsa_decrypt_btn = ttk.Button(btn_frame, text="Дешифровать", command=self.decrypt_rsa)
        self.rsa_decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.rsa_back_btn = ttk.Button(btn_frame, text="Назад", command=self.show_main_interface)
        self.rsa_back_btn.pack(side=tk.LEFT, padx=5)
    
    def show_rsa_interface(self):
        self.hide_all_interfaces()
        self.rsa_frame.pack()
        self.clear_output()
        self.print_output("=== Алгоритм RSA ===")
    
    def generate_primes(self):
        try:
            p = generate_prime(64)
            q = generate_prime(64)
            self.rsa_p_entry.delete(0, tk.END)
            self.rsa_q_entry.delete(0, tk.END)
            self.rsa_p_entry.insert(0, str(p))
            self.rsa_q_entry.insert(0, str(q))
            self.print_output(f"Сгенерированы простые числа: p={p}, q={q}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
    
    def encrypt_rsa(self):
        try:
            p = int(self.rsa_p_entry.get())
            q = int(self.rsa_q_entry.get())
            message = int(self.rsa_msg_entry.get())
            
            if not (simple_is_prime(p) and simple_is_prime(q)):
                messagebox.showerror("Ошибка", "p и q должны быть простыми!")
                return
            
            public_key, private_key = generate_rsa_keys(p, q)
            ciphertext = rsa_encrypt(message, public_key)
            
            self.clear_output()
            self.print_output(f"Открытый ключ (e, n): {public_key}")
            self.print_output(f"Закрытый ключ (d, n): {private_key}")
            self.print_output(f"Зашифровано: {ciphertext}")
            
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
    
    def decrypt_rsa(self):
        try:
            p = int(self.rsa_p_entry.get())
            q = int(self.rsa_q_entry.get())
            ciphertext = int(self.rsa_msg_entry.get())
            
            if not (simple_is_prime(p) and simple_is_prime(q)):
                messagebox.showerror("Ошибка", "p и q должны быть простыми!")
                return
            
            _, private_key = generate_rsa_keys(p, q)
            decrypted = rsa_decrypt(ciphertext, private_key)
            
            self.clear_output()
            self.print_output(f"Закрытый ключ (d, n): {private_key}")
            self.print_output(f"Расшифровано: {decrypted}")
            
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
    
    # ========== Диффи-Хеллман Интерфейс ==========
    def init_dh_interface(self):
        self.dh_frame = ttk.Frame(self.main_frame)
        
        input_frame = ttk.Frame(self.dh_frame)
        input_frame.pack(pady=10)
        
        ttk.Label(input_frame, text="Сообщение:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.dh_msg_entry = ttk.Entry(input_frame, width=40)
        self.dh_msg_entry.grid(row=0, column=1, padx=5, pady=5)
        self.dh_msg_entry.bind("<Button-3>", self.show_entry_menu)  # Привязка контекстного меню
        
        btn_frame = ttk.Frame(self.dh_frame)
        btn_frame.pack(pady=10)
        
        self.dh_generate_btn = ttk.Button(btn_frame, text="Генерировать параметры", command=self.generate_dh_params)
        self.dh_generate_btn.pack(side=tk.LEFT, padx=5)
        
        self.dh_encrypt_btn = ttk.Button(btn_frame, text="Зашифровать", command=self.encrypt_dh)
        self.dh_encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.dh_decrypt_btn = ttk.Button(btn_frame, text="Дешифровать", command=self.decrypt_dh)
        self.dh_decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.dh_back_btn = ttk.Button(btn_frame, text="Назад", command=self.show_main_interface)
        self.dh_back_btn.pack(side=tk.LEFT, padx=5)
    
    def show_dh_interface(self):
        self.hide_all_interfaces()
        self.dh_frame.pack()
        self.clear_output()
        self.print_output("=== Протокол Диффи-Хеллмана ===")
    
    def generate_dh_params(self):
        try:
            self.dh_p = generate_prime(64)
            self.dh_g = find_primitive_root(self.dh_p)
            self.dh_private_key = random.randint(2, self.dh_p - 2)
            self.dh_public_key = pow(self.dh_g, self.dh_private_key, self.dh_p)
            
            self.clear_output()
            self.print_output(f"Общие параметры:")
            self.print_output(f"p = {self.dh_p}")
            self.print_output(f"g = {self.dh_g}")
            self.print_output(f"\nВаш секретный ключ: {self.dh_private_key}")
            self.print_output(f"Ваш открытый ключ: {self.dh_public_key}")
            
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
    
    def encrypt_dh(self):
        try:
            if not all([self.dh_p, self.dh_g, self.dh_private_key]):
                messagebox.showerror("Ошибка", "Сначала сгенерируйте параметры!")
                return
                
            message = self.dh_msg_entry.get()
            if not message:
                messagebox.showerror("Ошибка", "Введите сообщение!")
                return
            
            # Имитация ключа другого участника
            other_private = random.randint(2, self.dh_p - 2)
            other_public = pow(self.dh_g, other_private, self.dh_p)
            
            # Общий секрет
            self.dh_shared_secret = pow(other_public, self.dh_private_key, self.dh_p)
            aes_key = generate_aes_key(self.dh_shared_secret)
            encrypted = encrypt_message(message, aes_key)
            
            self.clear_output()
            self.print_output(f"Чужой открытый ключ: {other_public}")
            self.print_output(f"Общий секрет: {self.dh_shared_secret}")
            self.print_output(f"\nЗашифрованное сообщение (hex):")
            self.print_output("="*50)
            self.print_output(encrypted)  # Чистая hex-строка
            self.print_output("="*50)
            self.print_output("Щелкните правой кнопкой мыши на тексте и выберите 'Копировать'")
            
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
    
    def decrypt_dh(self):
        try:
            if not self.dh_shared_secret:
                messagebox.showerror("Ошибка", "Сначала выполните шифрование для получения общего секрета!")
                return
                
            encrypted = self.dh_msg_entry.get().strip()
            
            # Удалить все символы, кроме hex
            encrypted = ''.join(c for c in encrypted if c.lower() in '0123456789abcdef')
            
            if not encrypted:
                messagebox.showerror("Ошибка", "Введите зашифрованное сообщение в hex-формате!")
                return
            
            # Проверка четности длины
            if len(encrypted) % 2 != 0:
                messagebox.showerror("Ошибка", 
                    f"Нечетная длина hex-строки ({len(encrypted)} символов)!\n"
                    "Должно быть четное количество символов.\n"
                    "Проверьте, что скопировали всю hex-строку.")
                return
            
            # Дешифрование
            aes_key = generate_aes_key(self.dh_shared_secret)
            decrypted = decrypt_message(encrypted, aes_key)
            
            self.clear_output()
            self.print_output("="*50)
            self.print_output(f"Исходное hex-сообщение: {encrypted}")
            self.print_output(f"Расшифрованный текст: '{decrypted}'")
            self.print_output("="*50)
            
        except Exception as e:
            messagebox.showerror("Ошибка дешифрования", f"Причина: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()