import random
import math
import hashlib

# ================== Общие вспомогательные функции ==================
def simple_is_prime(n):
    """Проверка числа на простоту (упрощенная)"""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def miller_rabin_is_prime(n, k=20):
    """Проверка числа на простоту с использованием теста Миллера-Рабина"""
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
    """Генерация большого простого числа"""
    while True:
        num = random.getrandbits(bits)
        if num % 2 == 0:
            num += 1
        if miller_rabin_is_prime(num):
            return num

def modular_inverse(a, m):
    """Вычисление модульного обратного элемента (a⁻¹ mod m)"""
    for d in range(1, m):
        if (d * a) % m == 1:
            return d
    raise ValueError(f"Обратный элемент для a={a} mod {m} не существует")

# ================== Реализация RSA ==================
def generate_rsa_keys(p, q, e=None):
    """Генерация ключей RSA"""
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
    
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_encrypt(message, public_key):
    """Шифрование сообщения RSA"""
    e, n = public_key
    if message < 0 or message >= n:
        raise ValueError(f"Сообщение должно быть в диапазоне [0, {n-1}]")
    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    """Дешифрование сообщения RSA"""
    d, n = private_key
    return pow(ciphertext, d, n)

def run_rsa():
    """Запуск программы RSA"""
    print("=" * 50)
    print("Реализация алгоритма RSA")
    print("=" * 50)
    
    try:
        p = int(input("Введите простое число p: "))
        q = int(input("Введите простое число q: "))
        message = int(input("Введите сообщение (число): "))
        
        if not (simple_is_prime(p) and simple_is_prime(q)):
            print("Предупреждение: p и q должны быть простыми числами!")
        
        public_key, private_key = generate_rsa_keys(p, q)
        e, n = public_key
        d, _ = private_key
        
        ciphertext = rsa_encrypt(message, public_key)
        decrypted = rsa_decrypt(ciphertext, private_key)
        
        print("\n" + "=" * 50)
        print(f"Открытый ключ (e, n): ({e}, {n})")
        print(f"Закрытый ключ (d, n): ({d}, {n})")
        print(f"Исходное сообщение: {message}")
        print(f"Зашифрованное сообщение: {ciphertext}")
        print(f"Расшифрованное сообщение: {decrypted}")
        print("=" * 50)
        
        if message == decrypted:
            print("Шифрование/дешифрование выполнено успешно!")
        else:
            print("Ошибка в работе алгоритма!")
            
    except Exception as e:
        print(f"\nОшибка: {str(e)}")

# ================== Реализация Диффи-Хеллмана ==================
def find_primitive_root(p):
    """Поиск первообразного корня для простого числа p"""
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

def diffie_hellman_exchange():
    """Процесс обмена ключами по Диффи-Хеллману"""
    p = generate_prime(64)
    g = find_primitive_root(p)
    
    print(f"Общие параметры (передаются открыто):")
    print(f"p = {p}")
    print(f"g = {g}")
    print("-" * 60)
    
    a = random.randint(2, p - 2)
    A = pow(g, a, p)
    
    b = random.randint(2, p - 2)
    B = pow(g, b, p)
    
    print(f"Алиса генерирует секретное число a = {a}")
    print(f"Алиса вычисляет A = g^a mod p = {A} и отправляет Бобу")
    print()
    print(f"Боб генерирует секретное число b = {b}")
    print(f"Боб вычисляет B = g^b mod p = {B} и отправляет Алисе")
    print("-" * 60)
    
    s_alice = pow(B, a, p)
    s_bob = pow(A, b, p)
    
    print(f"Алиса вычисляет общий секрет: s = B^a mod p = {s_alice}")
    print(f"Боб вычисляет общий секрет:   s = A^b mod p = {s_bob}")
    print("-" * 60)
    
    if s_alice == s_bob:
        print("Общий секретный ключ успешно создан!")
        print(f"Секретный ключ: {s_alice}")
    else:
        print("Ошибка: секретные ключи не совпадают!")
    
    return s_alice

def generate_aes_key(shared_secret):
    """Генерация AES-ключа из общего секрета"""
    secret_bytes = str(shared_secret).encode()
    return hashlib.sha256(secret_bytes).digest()

def encrypt_message(message, key):
    """Шифрование сообщения с помощью XOR"""
    message_bytes = message.encode('utf-8')
    key_stream = (key * ((len(message_bytes) // len(key)) + 1))[:len(message_bytes)]
    encrypted = bytes([m ^ k for m, k in zip(message_bytes, key_stream)])
    return encrypted.hex()

def decrypt_message(encrypted_hex, key):
    """Дешифрование сообщения"""
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    key_stream = (key * ((len(encrypted_bytes) // len(key)) + 1))[:len(encrypted_bytes)]
    decrypted = bytes([e ^ k for e, k in zip(encrypted_bytes, key_stream)])
    return decrypted.decode('utf-8', errors='ignore')

def run_diffie_hellman():
    """Запуск программы Диффи-Хеллмана"""
    print("=" * 60)
    print("Протокол обмена ключами Диффи-Хеллмана")
    print("=" * 60)
    
    shared_secret = diffie_hellman_exchange()
    aes_key = generate_aes_key(shared_secret)
    print(f"\nСгенерированный AES-ключ: {aes_key.hex()}")
    
    message = input("\nВведите сообщение для шифрования: ")
    encrypted = encrypt_message(message, aes_key)
    print(f"\nЗашифрованное сообщение (hex): {encrypted}")
    
    decrypted = decrypt_message(encrypted, aes_key)
    print(f"Расшифрованное сообщение: '{decrypted}'")
    print("=" * 60)

# ================== Главное меню ==================
def main_menu():
    """Главное меню программы"""
    while True:
        print("\n" + "=" * 50)
        print(" КРИПТОГРАФИЧЕСКИЕ АЛГОРИТМЫ")
        print("=" * 50)
        print("1. Алгоритм RSA (шифрование/дешифрование)")
        print("2. Протокол Диффи-Хеллмана (обмен ключами)")
        print("3. Выход")
        print("=" * 50)
        
        choice = input("Выберите алгоритм (1-3): ")
        
        if choice == '1':
            run_rsa()
        elif choice == '2':
            run_diffie_hellman()
        elif choice == '3':
            print("Программа завершена.")
            break
        else:
            print("Некорректный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main_menu()