import random
import math
import hashlib

def is_prime(n, k=20):
    """Проверка числа на простоту с использованием теста Миллера-Рабина"""
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Представим n-1 как (2^r)*d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Проведем k тестов
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
        if is_prime(num):
            return num

def find_primitive_root(p):
    """Поиск первообразного корня для простого числа p"""
    if p == 2:
        return 1
        
    # Факторизация p-1
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
    
    # Поиск первообразного корня
    for g in range(2, p):
        if all(pow(g, phi // factor, p) != 1 for factor in factors):
            return g
    return None

def diffie_hellman_exchange():
    """Процесс обмена ключами по Диффи-Хеллману"""
    # 1. Генерация общих параметров (открыто передаются)
    p = generate_prime(64)  # 64-битное простое число
    g = find_primitive_root(p)
    
    print(f"Общие параметры (передаются открыто):")
    print(f"p = {p}")
    print(f"g = {g}")
    print("-" * 60)
    
    # 2. Алиса генерирует секретный ключ
    a = random.randint(2, p - 2)
    A = pow(g, a, p)  # A = g^a mod p
    
    # 3. Боб генерирует секретный ключ
    b = random.randint(2, p - 2)
    B = pow(g, b, p)  # B = g^b mod p
    
    print(f"Алиса генерирует секретное число a = {a}")
    print(f"Алиса вычисляет A = g^a mod p = {A} и отправляет Бобу")
    print()
    print(f"Боб генерирует секретное число b = {b}")
    print(f"Боб вычисляет B = g^b mod p = {B} и отправляет Алисе")
    print("-" * 60)
    
    # 4. Алиса вычисляет общий секрет
    s_alice = pow(B, a, p)  # s = B^a mod p
    
    # 5. Боб вычисляет общий секрет
    s_bob = pow(A, b, p)  # s = A^b mod p
    
    print(f"Алиса вычисляет общий секрет: s = B^a mod p = {s_alice}")
    print(f"Боб вычисляет общий секрет:   s = A^b mod p = {s_bob}")
    print("-" * 60)
    
    # Проверка совпадения секретов
    if s_alice == s_bob:
        print("Общий секретный ключ успешно создан!")
        print(f"Секретный ключ: {s_alice}")
    else:
        print("Ошибка: секретные ключи не совпадают!")
    
    return s_alice

def generate_aes_key(shared_secret):
    """Генерация AES-ключа из общего секрета"""
    # Преобразуем число в байты
    secret_bytes = str(shared_secret).encode()
    
    # Используем SHA-256 для получения 256-битного ключа
    return hashlib.sha256(secret_bytes).digest()

def encrypt_message(message, key):
    """Шифрование сообщения с помощью XOR (для учебных целей)"""
    # Преобразуем сообщение в байты
    message_bytes = message.encode('utf-8')
    
    # Генерируем ключевой поток
    key_stream = (key * ((len(message_bytes) // len(key)) + 1))[:len(message_bytes)]
    
    # Шифруем с помощью XOR
    encrypted = bytes([m ^ k for m, k in zip(message_bytes, key_stream)])
    return encrypted.hex()

def decrypt_message(encrypted_hex, key):
    """Дешифрование сообщения"""
    # Преобразуем из hex в байты
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    
    # Генерируем ключевой поток
    key_stream = (key * ((len(encrypted_bytes) // len(key)) + 1))[:len(encrypted_bytes)]
    
    # Дешифруем с помощью XOR
    decrypted = bytes([e ^ k for e, k in zip(encrypted_bytes, key_stream)])
    return decrypted.decode('utf-8', errors='ignore')

def generate_aes_key(shared_secret):
     secret_bytes = str(shared_secret).encode()
     return hashlib.sha256(secret_bytes).digest()

def main():
    print("=" * 60)
    print("Протокол обмена ключами Диффи-Хеллмана")
    print("=" * 60)
    
    # Запуск обмена ключами
    shared_secret = diffie_hellman_exchange()
    
    # Генерация ключа шифрования
    aes_key = generate_aes_key(shared_secret)
    print(f"\nСгенерированный AES-ключ: {aes_key.hex()}")
    
    # Ввод сообщения
    message = input("\nВведите сообщение для шифрования: ")
    
    # Шифрование
    encrypted = encrypt_message(message, aes_key)
    print(f"\nЗашифрованное сообщение (hex): {encrypted}")
    
    # Дешифрование
    decrypted = decrypt_message(encrypted, aes_key)
    print(f"Расшифрованное сообщение: '{decrypted}'")
    print("=" * 60)

if __name__ == "__main__":
    main()