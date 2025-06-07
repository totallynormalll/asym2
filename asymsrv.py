# input_file_1.py (Server)

# Импортируем необходимые модули.
import socket # Модуль для работы с сетевыми сокетами (для создания сетевых соединений).
import threading # Модуль для работы с потоками (позволяет обрабатывать несколько клиентов одновременно).
from Crypto.PublicKey import RSA # Модуль для генерации и работы с RSA-ключами (асимметричное шифрование).
from Crypto.Cipher import PKCS1_OAEP, AES # Модули для различных алгоритмов шифрования:
                                          # PKCS1_OAEP - для RSA-шифрования (обычно для сессионных ключей).
                                          # AES - для Advanced Encryption Standard (симметричное шифрование данных).
from Crypto.Random import get_random_bytes # Модуль для генерации криптографически стойких случайных байтов.
import time # Модуль для работы со временем (используется для задержек).

# Определяем константы для сетевого сервера.
HOST = '127.0.0.1' # IP-адрес, на котором будет слушать сервер (localhost).
PORT = 9090        # Порт, на котором будет слушать сервер.

# Список для хранения информации о подключенных клиентах.
# Каждый элемент списка будет [соединение, адрес, публичный_RSA_ключ_клиента].
clients = []
# Мьютекс (замок) для безопасного доступа к списку `clients` из разных потоков.
# Это предотвращает проблемы, когда несколько потоков пытаются изменить список одновременно.
clients_lock = threading.Lock()
# Глобальный флаг, управляющий работой сервера. Если False, сервер начинает завершение работы.
server_running = True

def send_message_to_client(conn, client_public_key, message):
    """
    Функция для шифрования и отправки сообщения конкретному клиенту.
    
    Аргументы:
        conn (socket.socket): Объект сокета для связи с этим конкретным клиентом.
        client_public_key (Crypto.PublicKey.RSA._RSAobj): Публичный RSA-ключ клиента,
                                                            используется для шифрования сессионного ключа.
        message (str): Сообщение, которое нужно отправить.
    
    Возвращает:
        bool: True, если сообщение отправлено успешно, False в случае ошибки.
    """
    try:
        # 1. Генерируем случайный 16-байтовый сессионный ключ для AES.
        # Для каждого отправляемого сообщения генерируется новый сессионный ключ для повышения безопасности.
        session_key = get_random_bytes(16)
        # 2. Создаем объект для RSA-шифрования с использованием публичного ключа клиента.
        # Сессионный ключ будет зашифрован этим публичным ключом.
        cipher_rsa = PKCS1_OAEP.new(client_public_key)
        encrypted_key = cipher_rsa.encrypt(session_key) # Шифруем сессионный ключ.

        # 3. Шифруем само сообщение с использованием сессионного AES-ключа.
        # AES.MODE_EAX - режим, который обеспечивает конфиденциальность (шифрование) и аутентификацию/целостность (тег).
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        # encrypt_and_digest возвращает шифротекст и аутентификационный тег.
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode()) # Кодируем строку сообщения в байты.
        # Объединяем Nonce (одноразовый случайный вектор), Шифротекст и Тег в один пакет данных.
        # Nonce автоматически генерируется `AES.new` при создании объекта `cipher_aes`.
        data = cipher_aes.nonce + ciphertext + tag 

        # 4. Отправляем зашифрованный сессионный ключ и сообщение клиенту.
        # Сначала отправляем размер зашифрованного ключа (4 байта).
        conn.sendall(len(encrypted_key).to_bytes(4, 'big'))
        # Затем сам зашифрованный ключ.
        conn.sendall(encrypted_key)
        # Затем размер всего пакета данных сообщения (Nonce + Ciphertext + Tag, 4 байта).
        conn.sendall(len(data).to_bytes(4, 'big'))
        # Затем сам пакет данных.
        conn.sendall(data)
        return True # Отправка успешна.
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        # Ловим ошибки, если соединение с клиентом было разорвано во время отправки.
        print(f"Ошибка сокета при отправке сообщения клиенту: {e}")
        return False # Отправка не удалась.
    except Exception as e:
        # Ловим любые другие непредвиденные ошибки при шифровании/отправке.
        print(f"Неизвестная ошибка при отправке сообщения: {e}")
        return False # Отправка не удалась.

def handle_client(conn, addr):
    """
    Функция-обработчик для каждого подключенного клиента.
    Запускается в отдельном потоке для каждого клиента, чтобы сервер мог обрабатывать несколько клиентов одновременно.
    
    Аргументы:
        conn (socket.socket): Объект сокета, представляющий соединение с этим клиентом.
        addr (tuple): Кортеж (IP-адрес, порт) клиента.
    """
    client_public_key = None # Переменная для хранения публичного ключа этого клиента.
    try:
        # Важная проверка: Если сервер начал завершать работу (server_running = False)
        # между принятием соединения (`sock.accept()`) и запуском этого потока,
        # то новое соединение должно быть немедленно закрыто.
        if not server_running:
            print(f"handle_client: Отклонено подключение {addr} (сервер завершает работу).")
            try:
                conn.shutdown(socket.SHUT_RDWR) # Закрываем соединение.
                conn.close()
            except OSError: pass # Игнорируем ошибки, если сокет уже закрыт.
            return # Выходим из функции, не обрабатывая клиента.

        # 1. Генерация пары RSA-ключей для сервера (для взаимодействия с этим клиентом).
        # Каждый обработчик клиента генерирует свою пару ключей для обмена с конкретным клиентом.
        private_key = RSA.generate(2048) # Приватный ключ сервера (для этого клиента).
        public_key = private_key.publickey() # Публичный ключ сервера (для этого клиента).

        # 2. Обмен публичными ключами.
        # Сервер отправляет свой публичный ключ клиенту.
        conn.sendall(public_key.export_key())

        # Сервер получает публичный ключ клиента.
        client_key_data = conn.recv(1024) # Принимаем байты публичного ключа клиента.
        if not client_key_data: 
            print(f"Клиент {addr} отключился до обмена ключами (получены пустые данные).")
            return # Если данных нет, клиент отключился.

        client_public_key = RSA.import_key(client_key_data) # Импортируем байты как RSA-ключ.
        
        # 3. Обновляем публичный ключ клиента в глобальном списке `clients`.
        # Используем `clients_lock` для безопасного доступа к общему списку.
        with clients_lock:
            found = False
            for client_info in clients:
                if client_info[0] == conn: # Ищем клиента по его сокету.
                    client_info[2] = client_public_key # Обновляем публичный ключ.
                    found = True
                    break
            if not found: # Этого не должно происходить, если клиент был добавлен корректно в main.
                          # Но на всякий случай добавляем, если по какой-то причине не нашли.
                print(f"Предупреждение: Клиент {addr} не найден в общем списке при обновлении ключа. Добавляю.")
                clients.append([conn, addr, client_public_key])

        # 4. Основной цикл приема и обработки сообщений от клиента.
        while server_running: # Цикл продолжается, пока сервер работает.
            try:
                # 5. Получение и расшифровка сообщения от клиента.
                # Протокол тот же, что и при отправке: размер ключа, ключ, размер данных, данные.
                key_size_bytes = conn.recv(4)
                if not key_size_bytes: break # Если пустые данные, клиент отключился. 

                key_size = int.from_bytes(key_size_bytes, 'big')
                encrypted_key = conn.recv(key_size)
                if not encrypted_key: break 

                msg_size_bytes = conn.recv(4)
                if not msg_size_bytes: break 

                msg_size = int.from_bytes(msg_size_bytes, 'big')
                encrypted_msg = conn.recv(msg_size)
                if not encrypted_msg: break 

                # 6. Расшифровка сессионного ключа, зашифрованного публичным ключом сервера.
                cipher_rsa = PKCS1_OAEP.new(private_key) # Используем приватный ключ сервера.
                session_key = cipher_rsa.decrypt(encrypted_key)

                # 7. Разделение зашифрованного сообщения на Nonce, Шифротекст, Тег.
                nonce = encrypted_msg[:16]
                ciphertext = encrypted_msg[16:-16]
                tag = encrypted_msg[-16:]          
                
                # 8. Расшифровка самого сообщения с использованием AES.
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
                # decrypt_and_verify проверяет тег и расшифровывает. Выбрасывает ValueError при ошибке тега.
                decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
                message = decrypted.decode() # Декодируем байты в строку.

                print(f"Сообщение от {addr}: {message}") # Выводим принятое сообщение.

                # 9. Отправка ответа клиенту.
                response = f"Получено: {message}"
                send_message_to_client(conn, client_public_key, response) # Используем вспомогательную функцию для отправки.

            except ValueError as ve: 
                # Ошибка верификации тега (сообщение повреждено) или RSA-расшифровки.
                print(f"Ошибка верификации/дешифрования с клиентом {addr}: {ve}")
                break # Прекращаем обработку этого клиента.
            except (ConnectionResetError, BrokenPipeError) as e:
                # Клиент разорвал соединение.
                print(f"Клиент {addr} отключился: {e}")
                break
            except OSError as oe: 
                # Общая ошибка сокета. Если сервер завершает работу, это может быть ожидаемо.
                if server_running: 
                    print(f"Ошибка сокета с клиентом {addr}: {oe}")
                else: 
                    pass # Игнорируем, если сервер уже завершает работу.
                break
            except Exception as e:
                # Любая другая непредвиденная ошибка в цикле обработки.
                print(f"Неизвестная ошибка в цикле обработки клиента {addr}: {e}")
                break
    except Exception as e: 
        # Ошибка на раннем этапе (обмен ключами или инициализация).
        print(f"Ошибка на этапе обмена ключами/инициализации для клиента {addr}: {e}")
    finally:
        # Этот блок `finally` выполняется всегда, независимо от того, как завершился `try`.
        print(f"Обработчик клиента {addr} завершает работу...")
        try:
            # Корректно закрываем соединение с клиентом, если оно еще открыто.
            if conn and conn.fileno() != -1: # Проверяем, что сокет существует и открыт.
                conn.shutdown(socket.SHUT_RDWR) # Закрываем соединение на чтение и запись.
                conn.close() # Закрываем сокет.
                print(f"Соединение с клиентом {addr} успешно закрыто.")
        except OSError as e:
            # Игнорируем ошибку, если сокет уже был закрыт (например, основным потоком при завершении сервера).
            pass 
        except Exception as e:
            print(f"Неожиданная ошибка при закрытии сокета клиента {addr}: {e}")
        
        # Удаляем клиента из глобального списка `clients`.
        with clients_lock: # Используем мьютекс для безопасного изменения списка.
            clients[:] = [c for c in clients if c[0] != conn] # Создаем новый список без текущего клиента.
        print(f"Клиент {addr} отключен.")

def server_input():
    """
    Функция для обработки ввода с консоли сервера.
    Позволяет администратору сервера вводить сообщения для всех клиентов или остановить сервер.
    Запускается в отдельном потоке.
    """
    global server_running # Объявляем, что будем изменять глобальный флаг server_running.
    while server_running: # Цикл продолжается, пока сервер работает.
        command = input("Введите сообщение для всех клиентов (или 'stop' для завершения): ")
        
        if command.lower() == 'stop':
            print("Инициировано завершение работы сервера...")
            server_running = False # Устанавливаем флаг в False, чтобы сигнализировать о завершении.
            
            # Важный шаг: Подключаемся к своему же серверному сокету фиктивным сокетом, чтобы "разбудить" sock.accept().
            # Это необходимо, потому что `sock.accept()` блокирует основной поток, и без этого он не выйдет из ожидания.
            # После подключения, `accept()` вернет это фиктивное соединение, и основной поток увидит `server_running = False`.
            try:
                dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dummy_sock.connect((HOST, PORT)) # Подключаемся к серверу.
                dummy_sock.close() # Немедленно закрываем фиктивное соединение.
            except ConnectionRefusedError:
                # Если серверный сокет уже закрыт (например, по Ctrl+C), то ConnectionRefusedError.
                pass 
            except Exception as e:
                print(f"Ошибка при подключении dummy_sock: {e}")
            break # Выходим из цикла ввода.
        else:
            # Если команда не "stop", отправляем сообщение всем подключенным клиентам.
            with clients_lock: # Используем мьютекс для безопасного доступа к списку клиентов.
                # Создаем копию списка клиентов, у которых уже есть публичный ключ (обмен ключами завершен).
                clients_to_send = [(c_conn, c_addr, c_key) for c_conn, c_addr, c_key in clients if c_key]
                
                if not clients_to_send:
                    print("Нет подключенных клиентов для отправки сообщения.")
                    continue # Переходим к следующей итерации цикла.

                for client_conn, client_addr, client_key in clients_to_send:
                    print(f"Отправка сообщения клиенту {client_addr}")
                    success = send_message_to_client(client_conn, client_key, command) # Отправляем сообщение.
                    if not success:
                        print(f"Отправка сообщения клиенту {client_addr} не удалась. Обработчик клиента должен отключиться сам.")

def main():
    """
    Главная функция сервера:
    - Инициализация сокета сервера.
    - Запуск потока для консольного ввода.
    - Основной цикл ожидания и принятия клиентских подключений.
    - Корректное завершение работы сервера, включая закрытие всех соединений.
    """
    global server_running # Объявляем, что будем изменять глобальный флаг server_running.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Создаем серверный сокет (IPv4, TCP).
    try:
        sock.bind((HOST, PORT)) # Привязываем сокет к указанному IP-адресу и порту.
        sock.listen() # Начинаем прослушивать входящие соединения. (Максимальное количество ожидающих подключений по умолчанию).
        sock.settimeout(1) # Устанавливаем таймаут для sock.accept() в 1 секунду.
                           # Это позволяет `accept()` периодически прерываться и проверять флаг `server_running`.
    except Exception as e:
        print(f"Не удалось запустить сервер: {e}")
        return # Если сервер не может запуститься, выходим.

    # Запускаем поток для обработки ввода с консоли сервера.
    input_thread = threading.Thread(target=server_input)
    input_thread.daemon = True # Устанавливаем как поток-демон, чтобы он завершился с основной программой.
    input_thread.start() # Запускаем поток.

    print("Сервер запущен. Ожидание подключений...")
    
    try:
        while server_running: # Основной цикл сервера: продолжается, пока флаг server_running True.
            try:
                # Ожидаем входящее соединение. Если таймаут истечет (1 сек), будет выброшен socket.timeout.
                conn, addr = sock.accept()
                
                # CRITICAL: Проверяем server_running *немедленно* после accept().
                # Это предотвращает обработку новых подключений, если сервер уже начал завершение.
                if not server_running: 
                    # Это соединение, вероятно, является "фиктивным" сокетом, отправленным из `server_input`.
                    print(f"main: Получен сигнал остановки (фиктивное соединение от {addr}). Закрываю его.")
                    try: 
                        conn.shutdown(socket.SHUT_RDWR)
                        conn.close()
                    except OSError: pass # Игнорируем ошибки при закрытии.
                    break # Выходим из основного цикла сервера.
                
                # Добавляем информацию о новом клиенте в глобальный список.
                with clients_lock: # Используем мьютекс для безопасного доступа к списку.
                    clients.append([conn, addr, None]) # Публичный ключ пока неизвестен (None).
                print(f"Подключен клиент {addr}")
                # Запускаем новый поток для обработки этого конкретного клиента.
                threading.Thread(target=handle_client, args=(conn, addr)).start()
            except socket.timeout:
                # Если `accept()` истек таймаут, просто продолжаем цикл, чтобы снова проверить `server_running`.
                continue 
            except OSError as e: 
                # Это исключение не должно появляться при корректной работе с dummy_sock.
                # Если появляется, это непредвиденная ошибка.
                print(f"main: Неожиданная ошибка в socket.accept(): {e}")
                break # Выходим из цикла.
            except Exception as e:
                # Ловим любые другие непредвиденные ошибки в основном цикле.
                print(f"main: Неизвестная ошибка в основном цикле сервера: {e}")
                break
    except KeyboardInterrupt:
        # Ловим Ctrl+C, чтобы корректно завершить работу сервера.
        print("\nПолучен сигнал прерывания (Ctrl+C)")
    finally:
        # Этот блок `finally` всегда выполняется при выходе из `try-except` блока.
        print("Завершение работы сервера...")
        server_running = False # Убеждаемся, что флаг установлен в False.

        time.sleep(0.5) # Даем короткую паузу, чтобы другие потоки могли заметить изменение `server_running`.

        # Закрываем слушающий сокет сервера явно.
        try:
            if sock and sock.fileno() != -1: # Проверяем, что сокет существует и открыт.
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                print("Серверный слушающий сокет закрыт.")
        except OSError as e:
            # Игнорируем, если сокет уже был закрыт.
            print(f"Ошибка при закрытии серверного слушающего сокета в finally: {e} (Возможно, уже закрыт).")
        except Exception as e:
            print(f"Неожиданная ошибка при закрытии серверного слушающего сокета в finally: {e}")

        # Принудительно закрываем оставшиеся клиентские соединения.
        with clients_lock: # Используем мьютекс для безопасного доступа к списку клиентов.
            remaining_clients_count = len(clients)
            if remaining_clients_count > 0:
                print(f"Попытка принудительного закрытия {remaining_clients_count} оставшихся клиентских соединений...")
                # Итерируемся по копии списка `clients[:]`, чтобы избежать проблем с изменением списка во время итерации.
                for conn, addr, _ in clients[:]: 
                    try:
                        if conn and conn.fileno() != -1:
                            conn.shutdown(socket.SHUT_RDWR)
                            conn.close()
                            print(f"Принудительно закрыто соединение с {addr}.")
                    except OSError:
                        pass # Игнорируем ошибки, если сокет уже закрыт.
                    except Exception as e:
                        print(f"Ошибка при принудительном закрытии соединения с {addr}: {e}")
            clients.clear() # Очищаем список клиентов.

        # Ожидаем завершения потока ввода (если он еще активен).
        if input_thread.is_alive():
            print("Ожидание завершения потока ввода...")
            input_thread.join(timeout=2) # Ожидаем не более 2 секунд.
            if input_thread.is_alive():
                print("Поток ввода не завершился вовремя.")
        
        print("Сервер остановлен")

# Точка входа в программу.
if __name__ == "__main__":
    main() # Вызываем главную функцию при запуске скрипта.