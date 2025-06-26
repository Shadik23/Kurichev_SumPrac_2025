import math

def generate_rsa_keys(p, q, e=None):
    """Генерация ключей RSA"""
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Выбор открытой экспоненты e (если не задана)
    if e is None:
        e = find_coprime(phi)
    elif math.gcd(e, phi) != 1:
        raise ValueError(f"e={e} должно быть взаимно простым с φ(n)={phi}")
    
    # Вычисление закрытой экспоненты d
    d = modular_inverse(e, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_encrypt(message, public_key):
    """Шифрование сообщения"""
    e, n = public_key
    if message < 0 or message >= n:
        raise ValueError(f"Сообщение должно быть в диапазоне [0, {n-1}]")
    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    """Дешифрование сообщения"""
    d, n = private_key
    return pow(ciphertext, d, n)

def find_coprime(phi):
    """Поиск взаимно простого числа с φ(n)"""
    for e in range(3, phi, 2):
        if math.gcd(e, phi) == 1:
            return e
    raise ValueError(f"Не удалось найти подходящее e для φ(n)={phi}")

def modular_inverse(a, m):
    """Вычисление модульного обратного элемента (a⁻¹ mod m)"""
    for d in range(1, m):
        if (d * a) % m == 1:
            return d
    raise ValueError(f"Обратный элемент для a={a} mod {m} не существует")

def main():
    print("=" * 50)
    print("Реализация алгоритма RSA")
    print("=" * 50)
    
    # Ввод параметров
    try:
        p = int(input("Введите простое число p: "))
        q = int(input("Введите простое число q: "))
        message = int(input("Введите сообщение (число): "))
        
        # Проверка на простоту (упрощённая)
        if not (is_prime(p) and is_prime(q)):
            print("Предупреждение: p и q должны быть простыми числами!")
        
        # Генерация ключей
        public_key, private_key = generate_rsa_keys(p, q)
        e, n = public_key
        d, _ = private_key
        
        # Шифрование и дешифрование
        ciphertext = rsa_encrypt(message, public_key)
        decrypted = rsa_decrypt(ciphertext, private_key)
        
        # Вывод результатов
        print("\n" + "=" * 50)
        print(f"Открытый ключ (e, n): ({e}, {n})")
        print(f"Закрытый ключ (d, n): ({d}, {n})")
        print(f"Исходное сообщение: {message}")
        print(f"Зашифрованное сообщение: {ciphertext}")
        print(f"Расшифрованное сообщение: {decrypted}")
        print("=" * 50)
        
        # Проверка корректности
        if message == decrypted:
            print("Шифрование/дешифрование выполнено успешно!")
        else:
            print("Ошибка в работе алгоритма!")
            
    except Exception as e:
        print(f"\n Ошибка: {str(e)}")

def is_prime(n):
    """Проверка числа на простоту (для учебных целей)"""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

if __name__ == "__main__":
    main()