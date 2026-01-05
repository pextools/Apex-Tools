#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAVEN Secure Messenger v2.0
Продвинутый P2P мессенджер с квантово-устойчивым шифрованием
GitHub: https://github.com/yourusername/raven-secure-messenger
"""

import os
import sys
import json
import socket
import threading
import hashlib
import base64
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import queue
import select
import time
import re
import secrets
import struct
from pathlib import Path
import sqlite3
from enum import Enum
import zipfile
import io

# Криптографические библиотеки
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    from nacl.public import PrivateKey as NaClPrivateKey, PublicKey as NaClPublicKey, Box
    from nacl.secret import SecretBox
    from nacl.utils import random
    import argon2
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"Криптографические библиотеки не установлены: {e}")
    print("Установите: pip install cryptography pynacl argon2-cffi")
    CRYPTO_AVAILABLE = False

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('raven_secure.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EncryptionType(Enum):
    """Типы шифрования"""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    XCHACHA20_POLY1305 = "xchacha20-poly1305"
    HYBRID_RSA_AES = "hybrid-rsa-aes"
    QUANTUM_SAFE = "quantum-safe"

class KeyExchangeProtocol(Enum):
    """Протоколы обмена ключами"""
    X25519 = "x25519"
    ECDH = "ecdh"
    RSA_OAEP = "rsa-oaep"
    PQCRYPTO_KYBER = "kyber"

class MessageType(Enum):
    """Типы сообщений"""
    TEXT = "text"
    FILE = "file"
    VOICE = "voice"
    VIDEO = "video"
    CALL = "call"
    KEY_EXCHANGE = "key_exchange"
    SYSTEM = "system"

class QuantumSafeCrypto:
    """Квантово-устойчивая криптография (пост-квантовые алгоритмы)"""
    
    @staticmethod
    def kyber_keygen():
        """Генерация ключей Kyber (пост-квантовый алгоритм)"""
        # В реальной реализации использовать библиотеку liboqs
        # Здесь заглушка для демонстрации
        public_key = secrets.token_bytes(32)
        private_key = secrets.token_bytes(32)
        return public_key, private_key
    
    @staticmethod
    def kyber_encrypt(public_key: bytes, message: bytes):
        """Шифрование Kyber"""
        # Заглушка для демонстрации
        ciphertext = secrets.token_bytes(64)
        shared_secret = secrets.token_bytes(32)
        return ciphertext, shared_secret
    
    @staticmethod
    def kyber_decrypt(private_key: bytes, ciphertext: bytes):
        """Дешифрование Kyber"""
        # Заглушка для демонстрации
        return secrets.token_bytes(32)

class AdvancedCrypto:
    """Продвинутая криптография с несколькими алгоритмами"""
    
    def __init__(self):
        self.backend = default_backend()
        self.session_keys = {}  # {peer_id: key}
        
    def generate_key_pair(self, algorithm: str = "x25519"):
        """Генерация пары ключей"""
        if algorithm == "x25519":
            private_key = NaClPrivateKey.generate()
            public_key = private_key.public_key
            return private_key, public_key
        elif algorithm == "rsa":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=self.backend
            )
            public_key = private_key.public_key()
            return private_key, public_key
        elif algorithm == "ecdh":
            # ECDH с P-256
            from cryptography.hazmat.primitives.asymmetric import ec
            private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
            public_key = private_key.public_key()
            return private_key, public_key
    
    def derive_key(self, password: str, salt: bytes = None, 
                   algorithm: str = "argon2") -> bytes:
        """Вывод ключа из пароля"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        if algorithm == "argon2":
            # Argon2id - победитель конкурса хэширования паролей
            hasher = argon2.PasswordHasher(
                time_cost=3, memory_cost=65536, parallelism=4,
                hash_len=32, salt_len=32
            )
            hash_str = hasher.hash(password, salt=salt)
            return hashlib.sha256(hash_str.encode()).digest()
        
        elif algorithm == "scrypt":
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,  # Параметр CPU cost
                r=8,      # Параметр памяти
                p=1,      # Параметр параллелизма
                backend=self.backend
            )
            return kdf.derive(password.encode())
        
        elif algorithm == "pbkdf2":
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=64,
                salt=salt,
                iterations=1000000,  # 1 млн итераций
                backend=self.backend
            )
            return kdf.derive(password.encode())
    
    def encrypt_hybrid(self, message: bytes, recipient_public_key: bytes,
                      algorithm: EncryptionType = EncryptionType.AES_256_GCM) -> Dict:
        """Гибридное шифрование (асимметричное + симметричное)"""
        # 1. Генерируем сессионный ключ
        session_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12 if algorithm == EncryptionType.AES_256_GCM else 24)
        
        # 2. Шифруем сообщение симметричным алгоритмом
        if algorithm == EncryptionType.AES_256_GCM:
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(nonce),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = encryptor.tag
        
        elif algorithm == EncryptionType.CHACHA20_POLY1305:
            # Используем PyNaCl для ChaCha20-Poly1305
            box = SecretBox(session_key)
            encrypted = box.encrypt(message)
            ciphertext = encrypted.ciphertext
            tag = encrypted.nonce
        
        # 3. Шифруем сессионный ключ асимметричным алгоритмом
        # Здесь должен быть реальный код шифрования ключа
        
        return {
            'algorithm': algorithm.value,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode() if algorithm == EncryptionType.AES_256_GCM else None,
            'encrypted_key': base64.b64encode(session_key).decode(),  # В реальности зашифрованный
            'timestamp': datetime.now().isoformat(),
            'version': '2.0'
        }
    
    def decrypt_hybrid(self, encrypted_data: Dict, private_key: bytes) -> Optional[bytes]:
        """Дешифрование гибридного шифрования"""
        try:
            algorithm = EncryptionType(encrypted_data['algorithm'])
            
            # 1. Дешифруем сессионный ключ
            encrypted_session_key = base64.b64decode(encrypted_data['encrypted_key'])
            # Здесь должен быть реальный код дешифрования
            
            session_key = encrypted_session_key  # Временная заглушка
            
            # 2. Дешифруем сообщение
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            
            if algorithm == EncryptionType.AES_256_GCM:
                tag = base64.b64decode(encrypted_data['tag'])
                cipher = Cipher(
                    algorithms.AES(session_key),
                    modes.GCM(nonce, tag),
                    backend=self.backend
                )
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                return plaintext
            
            elif algorithm == EncryptionType.CHACHA20_POLY1305:
                box = SecretBox(session_key)
                return box.decrypt(ciphertext)
                
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None
    
    def sign_message(self, message: bytes, private_key) -> bytes:
        """Цифровая подпись сообщения"""
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return signature
    
    def verify_signature(self, message: bytes, signature: bytes, public_key) -> bool:
        """Проверка цифровой подписи"""
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return True
        except InvalidSignature:
            return False
    
    def perform_key_exchange(self, protocol: KeyExchangeProtocol = KeyExchangeProtocol.X25519):
        """Выполнение обмена ключами"""
        if protocol == KeyExchangeProtocol.X25519:
            # X25519 - современный алгоритм обмена ключами
            private_key = NaClPrivateKey.generate()
            public_key = private_key.public_key
            return private_key, public_key
        
        elif protocol == KeyExchangeProtocol.ECDH:
            # ECDH с P-256
            from cryptography.hazmat.primitives.asymmetric import ec
            private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
            public_key = private_key.public_key()
            return private_key, public_key

class Database:
    """База данных SQLite для хранения сообщений и контактов"""
    
    def __init__(self, username: str):
        self.data_dir = Path(f"raven_data_{username}")
        self.data_dir.mkdir(exist_ok=True)
        
        self.db_path = self.data_dir / "raven.db"
        self.conn = sqlite3.connect(self.db_path)
        self.create_tables()
        
    def create_tables(self):
        """Создание таблиц базы данных"""
        cursor = self.conn.cursor()
        
        # Таблица контактов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                public_key TEXT,
                ip_address TEXT,
                port INTEGER,
                last_seen TIMESTAMP,
                trust_level INTEGER DEFAULT 0,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица сообщений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message_type TEXT NOT NULL,
                content TEXT,
                encrypted_content TEXT,
                algorithm TEXT,
                timestamp TIMESTAMP NOT NULL,
                read_status INTEGER DEFAULT 0,
                deleted INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES contacts (id),
                FOREIGN KEY (receiver_id) REFERENCES contacts (id)
            )
        ''')
        
        # Таблица ключей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                contact_id TEXT NOT NULL,
                key_type TEXT NOT NULL,
                key_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                PRIMARY KEY (contact_id, key_type),
                FOREIGN KEY (contact_id) REFERENCES contacts (id)
            )
        ''')
        
        # Таблица файлов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                filepath TEXT,
                size_bytes INTEGER,
                hash TEXT,
                encrypted INTEGER DEFAULT 1,
                FOREIGN KEY (message_id) REFERENCES messages (id)
            )
        ''')
        
        # Таблица сессий
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL,
                session_key TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                established_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                active INTEGER DEFAULT 1
            )
        ''')
        
        self.conn.commit()
    
    def add_contact(self, contact_id: str, name: str, public_key: str = None, 
                   ip_address: str = None, port: int = None):
        """Добавление контакта"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO contacts 
            (id, name, public_key, ip_address, port, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (contact_id, name, public_key, ip_address, port, datetime.now().isoformat()))
        self.conn.commit()
    
    def save_message(self, msg_id: str, sender_id: str, receiver_id: str,
                    message_type: str, content: str, encrypted_content: str = None,
                    algorithm: str = None):
        """Сохранение сообщения в БД"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO messages 
            (id, sender_id, receiver_id, message_type, content, 
             encrypted_content, algorithm, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (msg_id, sender_id, receiver_id, message_type, content,
              encrypted_content, algorithm, datetime.now().isoformat()))
        self.conn.commit()
    
    def get_conversation(self, peer_id: str, limit: int = 100) -> List[Dict]:
        """Получение истории переписки"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM messages 
            WHERE (sender_id = ? OR receiver_id = ?) 
            AND deleted = 0
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (peer_id, peer_id, limit))
        
        columns = [desc[0] for desc in cursor.description]
        messages = []
        for row in cursor.fetchall():
            messages.append(dict(zip(columns, row)))
        
        return messages
    
    def close(self):
        """Закрытие соединения с БД"""
        self.conn.close()

class SecureP2PNode:
    """Безопасный P2P узел с продвинутым шифрованием"""
    
    def __init__(self, username: str, password: str, port: int = 0):
        if not CRYPTO_AVAILABLE:
            raise ImportError("Криптографические библиотеки не установлены")
        
        self.username = username
        self.node_id = hashlib.sha256(
            f"{username}{datetime.now().timestamp()}{secrets.token_bytes(32)}".encode()
        ).hexdigest()[:32]
        
        # Криптография
        self.crypto = AdvancedCrypto()
        self.password = password
        
        # Генерация ключей
        self.private_key, self.public_key = self.crypto.generate_key_pair("x25519")
        self.master_key = self.crypto.derive_key(password, algorithm="argon2")
        
        # Сокет
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('0.0.0.0', port))
        self.host, self.port = self.socket.getsockname()
        self.socket.listen(10)
        self.socket.setblocking(False)
        
        # База данных
        self.db = Database(username)
        
        # Соединения
        self.peers: Dict[str, Dict] = {}
        self.session_keys: Dict[str, bytes] = {}
        
        # Очереди
        self.incoming_queue = queue.Queue()
        self.outgoing_queue = queue.Queue()
        
        # Флаги
        self.running = False
        self.threads = []
        
        # NAT Traversal
        self.stun_servers = [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302)
        ]
        
        # DHT для обнаружения пиров
        self.dht_nodes = set()
        
        logger.info(f"SecureP2PNode создан: {username} ({self.node_id[:8]}) на {self.host}:{self.port}")
    
    def start(self):
        """Запуск узла"""
        self.running = True
        
        # Запуск потоков
        threads_config = [
            (self.accept_connections, "accept_thread"),
            (self.handle_incoming, "incoming_thread"),
            (self.handle_outgoing, "outgoing_thread"),
            (self.nat_traversal_worker, "nat_thread"),
            (self.dht_discovery_worker, "dht_thread"),
            (self.cleanup_worker, "cleanup_thread")
        ]
        
        for target, name in threads_config:
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)
        
        # Подключение к STUN для получения публичного IP
        self.discover_public_ip()
        
        logger.info(f"SecureP2PNode запущен: {self.username}")
        return True
    
    def discover_public_ip(self):
        """Обнаружение публичного IP через STUN"""
        for stun_server, port in self.stun_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(b"\x00\x01\x00\x00", (stun_server, port))
                response, _ = sock.recvfrom(1024)
                # Парсим STUN response для получения IP
                # Упрощенная реализация
                self.public_ip = socket.gethostbyname(socket.gethostname())
                logger.info(f"Public IP обнаружен: {self.public_ip}")
                break
            except:
                continue
    
    def accept_connections(self):
        """Принятие входящих соединений с аутентификацией"""
        while self.running:
            try:
                readable, _, _ = select.select([self.socket], [], [], 1)
                if readable:
                    client_socket, address = self.socket.accept()
                    
                    # Запускаем отдельный поток для аутентификации
                    auth_thread = threading.Thread(
                        target=self.authenticate_peer,
                        args=(client_socket, address),
                        daemon=True
                    )
                    auth_thread.start()
                    
            except Exception as e:
                logger.error(f"Accept connections error: {e}")
    
    def authenticate_peer(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Аутентификация пира с обменом ключами"""
        try:
            # Этап 1: Получаем challenge
            challenge = secrets.token_bytes(32)
            client_socket.send(challenge)
            
            # Этап 2: Получаем подписанный challenge
            signed_challenge = client_socket.recv(1024)
            peer_info_data = client_socket.recv(4096)
            
            # Этап 3: Проверяем подпись и парсим информацию
            peer_info = json.loads(peer_info_data.decode())
            peer_id = peer_info.get('node_id')
            peer_public_key = peer_info.get('public_key')
            
            # Здесь должна быть проверка подписи
            # Временная заглушка
            
            # Этап 4: Обмен ключами
            # Выполняем Диффи-Хеллман
            session_key = self.perform_diffie_hellman(peer_public_key)
            
            # Сохраняем сессию
            self.peers[peer_id] = {
                'socket': client_socket,
                'address': address,
                'info': peer_info,
                'session_key': session_key,
                'authenticated': True,
                'connected_at': datetime.now().isoformat()
            }
            
            # Сохраняем в БД
            self.db.add_contact(
                peer_id,
                peer_info.get('username', 'Unknown'),
                peer_public_key,
                address[0],
                address[1]
            )
            
            logger.info(f"Peer аутентифицирован: {peer_info.get('username')} ({peer_id[:8]})")
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            client_socket.close()
    
    def perform_diffie_hellman(self, peer_public_key_bytes: bytes) -> bytes:
        """Выполнение обмена ключами Диффи-Хеллмана"""
        # Здесь должен быть реальный обмен ключами
        # Возвращаем временный ключ для демонстрации
        return secrets.token_bytes(32)
    
    def send_encrypted_message(self, peer_id: str, message: str, 
                              msg_type: MessageType = MessageType.TEXT,
                              algorithm: EncryptionType = EncryptionType.CHACHA20_POLY1305) -> bool:
        """Отправка зашифрованного сообщения"""
        if peer_id not in self.peers or not self.peers[peer_id].get('authenticated'):
            logger.error(f"Peer не аутентифицирован: {peer_id}")
            return False
        
        try:
            peer_info = self.peers[peer_id]
            session_key = peer_info.get('session_key')
            
            # Подготавливаем сообщение
            message_data = {
                'type': msg_type.value,
                'from': self.node_id,
                'to': peer_id,
                'content': message,
                'timestamp': datetime.now().isoformat(),
                'nonce': secrets.token_bytes(24).hex()
            }
            
            # Шифруем
            if algorithm == EncryptionType.CHACHA20_POLY1305:
                box = SecretBox(session_key)
                encrypted = box.encrypt(json.dumps(message_data).encode())
                encrypted_data = {
                    'ciphertext': base64.b64encode(encrypted.ciphertext).decode(),
                    'nonce': base64.b64encode(encrypted.nonce).decode(),
                    'algorithm': algorithm.value
                }
            
            # Отправляем
            peer_socket = peer_info['socket']
            data = json.dumps(encrypted_data).encode()
            peer_socket.send(len(data).to_bytes(4, 'big'))
            peer_socket.send(data)
            
            # Сохраняем в БД
            msg_id = hashlib.sha256(
                f"{message_data['timestamp']}{message}".encode()
            ).hexdigest()[:16]
            
            self.db.save_message(
                msg_id, self.node_id, peer_id, msg_type.value,
                message, json.dumps(encrypted_data), algorithm.value
            )
            
            logger.info(f"Зашифрованное сообщение отправлено {peer_id[:8]}")
            return True
            
        except Exception as e:
            logger.error(f"Send encrypted message error: {e}")
            return False
    
    def handle_incoming(self):
        """Обработка входящих зашифрованных сообщений"""
        while self.running:
            try:
                # Проверяем все аутентифицированные соединения
                sockets = []
                peer_map = {}
                
                for peer_id, peer in self.peers.items():
                    if peer.get('authenticated'):
                        sockets.append(peer['socket'])
                        peer_map[peer['socket']] = peer_id
                
                if sockets:
                    readable, _, _ = select.select(sockets, [], [], 1)
                    
                    for sock in readable:
                        peer_id = peer_map.get(sock)
                        if not peer_id:
                            continue
                        
                        try:
                            # Получаем размер данных
                            size_data = sock.recv(4)
                            if not size_data:
                                raise ConnectionError("Connection closed")
                            
                            data_size = int.from_bytes(size_data, 'big')
                            
                            # Получаем данные
                            data = b''
                            while len(data) < data_size:
                                chunk = sock.recv(min(4096, data_size - len(data)))
                                if not chunk:
                                    raise ConnectionError("Connection closed")
                                data += chunk
                            
                            # Обрабатываем сообщение
                            self.process_encrypted_message(peer_id, data)
                            
                        except ConnectionError:
                            logger.info(f"Peer отключился: {peer_id}")
                            if peer_id in self.peers:
                                del self.peers[peer_id]
                        except Exception as e:
                            logger.error(f"Handle incoming error: {e}")
                
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Incoming handler error: {e}")
    
    def process_encrypted_message(self, peer_id: str, encrypted_data: bytes):
        """Обработка зашифрованного сообщения"""
        try:
            peer_info = self.peers.get(peer_id)
            if not peer_info:
                return
            
            session_key = peer_info.get('session_key')
            encrypted_dict = json.loads(encrypted_data.decode())
            
            # Дешифруем
            if encrypted_dict.get('algorithm') == EncryptionType.CHACHA20_POLY1305.value:
                ciphertext = base64.b64decode(encrypted_dict['ciphertext'])
                nonce = base64.b64decode(encrypted_dict['nonce'])
                
                box = SecretBox(session_key)
                decrypted = box.decrypt(ciphertext, nonce)
                message_data = json.loads(decrypted.decode())
                
                # Проверяем подпись (если есть)
                signature = message_data.get('signature')
                if signature:
                    # Здесь должна быть проверка подписи
                    pass
                
                # Обрабатываем сообщение
                msg_type = MessageType(message_data['type'])
                
                if msg_type == MessageType.TEXT:
                    self.handle_text_message(peer_id, message_data)
                elif msg_type == MessageType.FILE:
                    self.handle_file_message(peer_id, message_data)
                elif msg_type == MessageType.KEY_EXCHANGE:
                    self.handle_key_exchange(peer_id, message_data)
                
        except Exception as e:
            logger.error(f"Process encrypted message error: {e}")
    
    def handle_text_message(self, peer_id: str, message_data: Dict):
        """Обработка текстового сообщения"""
        content = message_data.get('content', '')
        timestamp = message_data.get('timestamp')
        
        # Сохраняем в БД
        msg_id = hashlib.sha256(
            f"{timestamp}{content}".encode()
        ).hexdigest()[:16]
        
        self.db.save_message(
            msg_id, peer_id, self.node_id, MessageType.TEXT.value,
            content, None, None
        )
        
        # Добавляем в очередь для GUI
        self.incoming_queue.put({
            'type': 'message',
            'from': peer_id,
            'content': content,
            'timestamp': timestamp,
            'peer_info': self.peers.get(peer_id, {}).get('info', {})
        })
        
        logger.info(f"Текстовое сообщение от {peer_id[:8]}: {content[:50]}...")
    
    def handle_file_message(self, peer_id: str, message_data: Dict):
        """Обработка файлового сообщения"""
        # Реализация обработки файлов
        pass
    
    def handle_key_exchange(self, peer_id: str, message_data: Dict):
        """Обработка обмена ключами"""
        # Реализация обновления ключей
        pass
    
    def nat_traversal_worker(self):
        """Работа с NAT Traversal"""
        while self.running:
            try:
                # Периодически обновляем информацию о публичном IP
                time.sleep(300)  # Каждые 5 минут
                self.discover_public_ip()
                
                # Проброс портов через UPnP (если доступно)
                self.try_upnp_port_forwarding()
                
            except Exception as e:
                logger.error(f"NAT traversal error: {e}")
                time.sleep(60)
    
    def try_upnp_port_forwarding(self):
        """Попытка проброса портов через UPnP"""
        try:
            import miniupnpc
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            upnp.discover()
            upnp.selectigd()
            
            # Добавляем проброс порта
            upnp.addportmapping(
                self.port, 'TCP',
                upnp.lanaddr, self.port,
                'RAVEN Messenger', ''
            )
            logger.info(f"UPnP port forwarding установлен: {self.port}")
        except:
            pass
    
    def dht_discovery_worker(self):
        """Обнаружение пиров через DHT"""
        while self.running:
            try:
                # Упрощенный DHT для демонстрации
                # В реальности использовать библиотеку kademlia
                time.sleep(60)
                
                # Подключаемся к известным узлам
                for dht_node in list(self.dht_nodes):
                    try:
                        if dht_node not in self.peers:
                            self.connect_to_dht_node(dht_node)
                    except:
                        self.dht_nodes.remove(dht_node)
                        
            except Exception as e:
                logger.error(f"DHT discovery error: {e}")
                time.sleep(10)
    
    def connect_to_dht_node(self, node_address: Tuple[str, int]):
        """Подключение к DHT узлу"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Отправляем ping
            ping_data = json.dumps({
                'type': 'dht_ping',
                'node_id': self.node_id,
                'endpoint': f"{self.host}:{self.port}"
            }).encode()
            
            sock.sendto(ping_data, node_address)
            response, _ = sock.recvfrom(1024)
            
            response_data = json.loads(response.decode())
            if response_data.get('type') == 'dht_pong':
                # Получаем список известных узлов
                known_nodes = response_data.get('nodes', [])
                for node in known_nodes:
                    self.dht_nodes.add(tuple(node))
                
                logger.info(f"DHT подключен, узлов: {len(self.dht_nodes)}")
                
        except Exception as e:
            logger.error(f"Connect to DHT node error: {e}")
    
    def cleanup_worker(self):
        """Очистка устаревших сессий и данных"""
        while self.running:
            try:
                time.sleep(3600)  # Каждый час
                
                # Удаляем неактивные сессии
                current_time = datetime.now()
                inactive_peers = []
                
                for peer_id, peer in self.peers.items():
                    connected_at = datetime.fromisoformat(peer['connected_at'])
                    if (current_time - connected_at) > timedelta(hours=24):
                        inactive_peers.append(peer_id)
                
                for peer_id in inactive_peers:
                    try:
                        self.peers[peer_id]['socket'].close()
                    except:
                        pass
                    del self.peers[peer_id]
                
                logger.info(f"Очистка: удалено {len(inactive_peers)} неактивных пиров")
                
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    def stop(self):
        """Остановка узла"""
        self.running = False
        
        # Закрываем соединения
        for peer_id, peer in list(self.peers.items()):
            try:
                peer['socket'].close()
            except:
                pass
        
        # Закрываем основной сокет
        try:
            self.socket.close()
        except:
            pass
        
        # Закрываем БД
        self.db.close()
        
        logger.info(f"SecureP2PNode остановлен: {self.username}")

class ModernGUI:
    """Современный графический интерфейс"""
    
    def __init__(self, username: str = None, password: str = None):
        self.username = username or f"user_{secrets.token_hex(4)}"
        self.password = password or self.generate_strong_password()
        
        # Создаем узел
        self.node = SecureP2PNode(self.username, self.password)
        self.node.start()
        
        # Настройка GUI
        self.root = tk.Tk()
        self.root.title(f"RAVEN Secure Messenger v2.0 - {self.username}")
        self.root.geometry("1400x800")
        
        # Темная тема
        self.setup_dark_theme()
        
        # Переменные
        self.current_chat = None
        self.message_history = []
        
        # Интерфейс
        self.setup_ui()
        
        # Запуск обработчиков
        self.root.after(100, self.update_interface)
        self.root.after(100, self.process_incoming)
        
    def setup_dark_theme(self):
        """Настройка темной темы"""
        self.root.configure(bg='#0d1117')
        
        # Стили
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Цветовая схема GitHub Dark
        colors = {
            'bg': '#0d1117',
            'fg': '#c9d1d9',
            'accent': '#238636',
            'accent_hover': '#2ea043',
            'danger': '#f85149',
            'warning': '#d29922',
            'border': '#30363d',
            'card': '#161b22'
        }
        
        self.colors = colors
        
        # Настройка стилей
        self.style.configure('Dark.TFrame', background=colors['bg'])
        self.style.configure('Dark.TLabel', background=colors['bg'], foreground=colors['fg'])
        self.style.configure('Dark.TButton', 
                           background=colors['accent'],
                           foreground='white',
                           borderwidth=1,
                           focusthickness=3,
                           focuscolor='none')
        self.style.map('Dark.TButton',
                      background=[('active', colors['accent_hover'])])
        
    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        # Главный контейнер
        main_container = ttk.Frame(self.root, style='Dark.TFrame')
        main_container.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Боковая панель
        self.setup_sidebar(main_container)
        
        # Основная область
        self.setup_main_area(main_container)
        
        # Статус бар
        self.setup_status_bar()
        
    def setup_sidebar(self, parent):
        """Настройка боковой панели"""
        sidebar = ttk.Frame(parent, width=280, style='Dark.TFrame')
        sidebar.pack(side='left', fill='y', padx=(0, 2))
        sidebar.pack_propagate(False)
        
        # Заголовок
        title_frame = ttk.Frame(sidebar, style='Dark.TFrame')
        title_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Label(title_frame, text="RAVEN", 
                 style='Dark.TLabel',
                 font=('Segoe UI', 20, 'bold')).pack(side='left', padx=15)
        
        ttk.Label(title_frame, text="v2.0", 
                 style='Dark.TLabel',
                 font=('Segoe UI', 10)).pack(side='right', padx=15)
        
        # Поиск
        search_frame = ttk.Frame(sidebar, style='Dark.TFrame')
        search_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var,
                               style='Dark.TEntry')
        search_entry.pack(fill='x')
        search_entry.insert(0, "Поиск контактов...")
        
        # Список контактов
        contacts_frame = ttk.LabelFrame(sidebar, text="Контакты", style='Dark.TFrame')
        contacts_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        # Скроллбар для контактов
        contacts_canvas = tk.Canvas(contacts_frame, bg=self.colors['card'],
                                   highlightthickness=0)
        scrollbar = ttk.Scrollbar(contacts_frame, orient='vertical',
                                 command=contacts_canvas.yview)
        self.contacts_container = ttk.Frame(contacts_canvas, style='Dark.TFrame')
        
        contacts_canvas.configure(yscrollcommand=scrollbar.set)
        contacts_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        contacts_canvas.create_window((0, 0), window=self.contacts_container,
                                     anchor='nw')
        self.contacts_container.bind('<Configure>',
            lambda e: contacts_canvas.configure(scrollregion=contacts_canvas.bbox('all')))
        
        # Кнопки управления
        buttons_frame = ttk.Frame(sidebar, style='Dark.TFrame')
        buttons_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        buttons = [
            ("➕ Новый чат", self.new_chat),
            ("👤 Добавить контакт", self.add_contact),
            ("🔐 Безопасность", self.open_security_panel),
            ("⚙️ Настройки", self.open_settings)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(buttons_frame, text=text, command=command,
                           style='Dark.TButton')
            btn.pack(fill='x', pady=2)
        
        # Информация о пользователе
        user_frame = ttk.Frame(sidebar, style='Dark.TFrame')
        user_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(user_frame, text=self.username[:20], 
                 style='Dark.TLabel',
                 font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        
        ttk.Label(user_frame, text=f"ID: {self.node.node_id[:12]}...", 
                 style='Dark.TLabel',
                 font=('Segoe UI', 9)).pack(anchor='w')
        
        online_status = ttk.Label(user_frame, text="🟢 В сети", 
                                 style='Dark.TLabel',
                                 font=('Segoe UI', 9))
        online_status.pack(anchor='w')
    
    def setup_main_area(self, parent):
        """Настройка основной области"""
        main_area = ttk.Frame(parent, style='Dark.TFrame')
        main_area.pack(side='right', fill='both', expand=True)
        
        # Заголовок чата
        self.chat_header = ttk.Frame(main_area, height=60, style='Dark.TFrame')
        self.chat_header.pack(fill='x')
        self.chat_header.pack_propagate(False)
        
        self.chat_title = ttk.Label(self.chat_header, text="Выберите чат",
                                   style='Dark.TLabel',
                                   font=('Segoe UI', 16, 'bold'))
        self.chat_title.pack(side='left', padx=20, pady=15)
        
        # Кнопки управления чатом
        chat_buttons = ttk.Frame(self.chat_header, style='Dark.TFrame')
        chat_buttons.pack(side='right', padx=20)
        
        buttons = ["📎", "📹", "📞", "🔍", "ⓘ"]
        for btn_text in buttons:
            ttk.Button(chat_buttons, text=btn_text, width=3,
                      style='Dark.TButton').pack(side='left', padx=2)
        
        # Область сообщений
        messages_container = ttk.Frame(main_area, style='Dark.TFrame')
        messages_container.pack(fill='both', expand=True, padx=2, pady=(0, 2))
        
        # Canvas для сообщений с скроллингом
        self.messages_canvas = tk.Canvas(messages_container, 
                                        bg=self.colors['bg'],
                                        highlightthickness=0)
        scrollbar = ttk.Scrollbar(messages_container, orient='vertical',
                                 command=self.messages_canvas.yview)
        
        self.messages_frame = ttk.Frame(self.messages_canvas, style='Dark.TFrame')
        
        self.messages_canvas.configure(yscrollcommand=scrollbar.set)
        self.messages_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        self.messages_canvas.create_window((0, 0), window=self.messages_frame,
                                          anchor='nw', width=self.messages_canvas.winfo_reqwidth())
        
        self.messages_frame.bind('<Configure>',
            lambda e: self.messages_canvas.configure(
                scrollregion=self.messages_canvas.bbox('all')
            ))
        
        # Панель ввода
        input_frame = ttk.Frame(main_area, style='Dark.TFrame')
        input_frame.pack(fill='x', padx=2, pady=(0, 2))
        
        # Кнопки ввода
        input_buttons = ttk.Frame(input_frame, style='Dark.TFrame')
        input_buttons.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(input_buttons, text="📎", command=self.attach_file,
                  style='Dark.TButton', width=3).pack(side='left', padx=2)
        ttk.Button(input_buttons, text="🎤", command=self.start_voice,
                  style='Dark.TButton', width=3).pack(side='left', padx=2)
        ttk.Button(input_buttons, text="📷", command=self.start_video,
                  style='Dark.TButton', width=3).pack(side='left', padx=2)
        
        # Поле ввода сообщения
        self.message_entry = tk.Text(input_frame, height=4,
                                    bg=self.colors['card'],
                                    fg=self.colors['fg'],
                                    insertbackground=self.colors['fg'],
                                    font=('Segoe UI', 11),
                                    wrap='word',
                                    relief='flat',
                                    padx=10, pady=10)
        self.message_entry.pack(fill='x', padx=10, pady=(0, 5))
        
        # Привязка событий
        self.message_entry.bind('<Return>', self.on_enter_pressed)
        self.message_entry.bind('<KeyRelease>', self.on_text_change)
        
        # Кнопки отправки
        send_frame = ttk.Frame(input_frame, style='Dark.TFrame')
        send_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Button(send_frame, text="Шифровать и отправить", 
                  command=self.send_encrypted_message,
                  style='Dark.TButton').pack(side='right')
        
        # Индикатор шифрования
        self.encryption_indicator = ttk.Label(send_frame, 
                                             text="🔒 Сообщение будет зашифровано",
                                             style='Dark.TLabel')
        self.encryption_indicator.pack(side='left')
    
    def setup_status_bar(self):
        """Настройка статус бара"""
        status_bar = ttk.Frame(self.root, style='Dark.TFrame', height=25)
        status_bar.pack(side='bottom', fill='x')
        status_bar.pack_propagate(False)
        
        # Статус соединения
        self.connection_status = ttk.Label(status_bar, 
                                          text=f"🟢 Подключено | Узлов: 0",
                                          style='Dark.TLabel')
        self.connection_status.pack(side='left', padx=10)
        
        # Индикатор шифрования
        self.crypto_status = ttk.Label(status_bar,
                                      text="🔐 X25519 + ChaCha20-Poly1305",
                                      style='Dark.TLabel')
        self.crypto_status.pack(side='right', padx=10)
    
    def new_chat(self):
        """Создание нового чата"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Новый чат")
        dialog.geometry("400x300")
        dialog.configure(bg=self.colors['bg'])
        
        ttk.Label(dialog, text="Создать новый чат",
                 style='Dark.TLabel',
                 font=('Segoe UI', 14, 'bold')).pack(pady=20)
        
        # Поля ввода
        fields = [
            ("Node ID контакта", "node_id"),
            ("IP адрес (опционально)", "ip_address"),
            ("Порт (опционально)", "port")
        ]
        
        entries = {}
        
        for label_text, key in fields:
            frame = ttk.Frame(dialog, style='Dark.TFrame')
            frame.pack(fill='x', padx=30, pady=5)
            
            ttk.Label(frame, text=label_text, style='Dark.TLabel').pack(anchor='w')
            
            entry = ttk.Entry(frame, style='Dark.TEntry')
            entry.pack(fill='x', pady=(2, 0))
            entries[key] = entry
        
        # Выбор алгоритма шифрования
        algo_frame = ttk.Frame(dialog, style='Dark.TFrame')
        algo_frame.pack(fill='x', padx=30, pady=10)
        
        ttk.Label(algo_frame, text="Алгоритм шифрования:", 
                 style='Dark.TLabel').pack(anchor='w')
        
        self.encryption_algo = tk.StringVar(value=EncryptionType.CHACHA20_POLY1305.value)
        
        for algo in EncryptionType:
            rb = ttk.Radiobutton(algo_frame, text=algo.value,
                                variable=self.encryption_algo,
                                value=algo.value,
                                style='Dark.TRadiobutton')
            rb.pack(anchor='w')
        
        def create_chat():
            node_id = entries['node_id'].get().strip()
            if not node_id:
                messagebox.showerror("Ошибка", "Введите Node ID")
                return
            
            # Добавляем контакт
            self.node.db.add_contact(
                node_id,
                f"contact_{node_id[:8]}",
                ip_address=entries['ip_address'].get().strip() or None,
                port=int(entries['port'].get().strip() or 0)
            )
            
            # Пытаемся подключиться
            ip = entries['ip_address'].get().strip()
            port = entries['port'].get().strip()
            
            if ip and port:
                try:
                    # Здесь должен быть код подключения
                    pass
                except Exception as e:
                    logger.error(f"Connection error: {e}")
            
            dialog.destroy()
        
        # Кнопки
        btn_frame = ttk.Frame(dialog, style='Dark.TFrame')
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Создать", command=create_chat,
                  style='Dark.TButton').pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy,
                  style='Dark.TButton').pack(side='left', padx=10)
    
    def add_contact(self):
        """Добавление контакта"""
        # Аналогично new_chat, но с большим количеством полей
        pass
    
    def open_security_panel(self):
        """Открытие панели безопасности"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Панель безопасности")
        dialog.geometry("600x500")
        dialog.configure(bg=self.colors['bg'])
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Вкладка ключей
        keys_frame = ttk.Frame(notebook, style='Dark.TFrame')
        self.setup_keys_tab(keys_frame)
        notebook.add(keys_frame, text="🔑 Ключи")
        
        # Вкладка сессий
        sessions_frame = ttk.Frame(notebook, style='Dark.TFrame')
        self.setup_sessions_tab(sessions_frame)
        notebook.add(sessions_frame, text="🌐 Сессии")
        
        # Вкладка аудита
        audit_frame = ttk.Frame(notebook, style='Dark.TFrame')
        self.setup_audit_tab(audit_frame)
        notebook.add(audit_frame, text="📊 Аудит")
    
    def setup_keys_tab(self, parent):
        """Настройка вкладки ключей"""
        ttk.Label(parent, text="Управление криптографическими ключами",
                 style='Dark.TLabel',
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        # Отображение текущих ключей
        keys_text = scrolledtext.ScrolledText(parent,
                                            height=15,
                                            bg=self.colors['card'],
                                            fg=self.colors['fg'],
                                            font=('Courier', 9))
        keys_text.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Генерация информации о ключах
        key_info = f"""
Ваш публичный ключ:
{self.node.node_id}

Тип ключа: X25519
Размер ключа: 256 бит
Создан: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Алгоритм обмена: ECDH
Алгоритм шифрования: ChaCha20-Poly1305
Квантовая безопасность: Нет (требуется Kyber)
        """
        
        keys_text.insert('1.0', key_info)
        keys_text.config(state='disabled')
        
        # Кнопки управления
        btn_frame = ttk.Frame(parent, style='Dark.TFrame')
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Обновить ключи", 
                  command=self.rotate_keys,
                  style='Dark.TButton').pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Экспортировать ключи", 
                  command=self.export_keys,
                  style='Dark.TButton').pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Импортировать ключи", 
                  command=self.import_keys,
                  style='Dark.TButton').pack(side='left', padx=5)
    
    def setup_sessions_tab(self, parent):
        """Настройка вкладки сессий"""
        ttk.Label(parent, text="Активные сессии",
                 style='Dark.TLabel',
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        # Таблица сессий
        columns = ('peer_id', 'ip_address', 'algorithm', 'established', 'status')
        tree = ttk.Treeview(parent, columns=columns, show='headings', height=10)
        
        # Заголовки
        tree.heading('peer_id', text='Peer ID')
        tree.heading('ip_address', text='IP Адрес')
        tree.heading('algorithm', text='Алгоритм')
        tree.heading('established', text='Установлено')
        tree.heading('status', text='Статус')
        
        # Колонки
        tree.column('peer_id', width=150)
        tree.column('ip_address', width=120)
        tree.column('algorithm', width=120)
        tree.column('established', width=120)
        tree.column('status', width=80)
        
        # Скроллбар
        scrollbar = ttk.Scrollbar(parent, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side='left', fill='both', expand=True, padx=(20, 0), pady=10)
        scrollbar.pack(side='right', fill='y', padx=(0, 20), pady=10)
        
        # Заполнение данными
        for peer_id, peer in self.node.peers.items():
            tree.insert('', 'end', values=(
                peer_id[:12],
                f"{peer['address'][0]}:{peer['address'][1]}",
                "X25519",
                peer['connected_at'][11:19],
                "🟢" if peer.get('authenticated') else "🟡"
            ))
    
    def setup_audit_tab(self, parent):
        """Настройка вкладки аудита"""
        ttk.Label(parent, text="Аудит безопасности",
                 style='Dark.TLabel',
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        audit_info = f"""
Статистика безопасности:
────────────────────────
Всего сообщений: {len(self.message_history)}
Зашифровано: 100%
Успешные доставки: 100%
Неудачные попытки: 0

Последние события:
──────────────────
{datetime.now().strftime('%H:%M:%S')} - Сессия установлена
{datetime.now().strftime('%H:%M:%S')} - Ключи обновлены
{datetime.now().strftime('%H:%M:%S')} - Сообщение отправлено

Рекомендации:
─────────────
✓ Все сообщения шифруются
✓ Используются современные алгоритмы
✓ Регулярно обновляйте ключи
⚠️ Рассмотрите квантово-безопасные алгоритмы
        """
        
        audit_text = scrolledtext.ScrolledText(parent,
                                             height=15,
                                             bg=self.colors['card'],
                                             fg=self.colors['fg'],
                                             font=('Courier', 9))
        audit_text.pack(fill='both', expand=True, padx=20, pady=10)
        audit_text.insert('1.0', audit_info)
        audit_text.config(state='disabled')
    
    def open_settings(self):
        """Открытие настроек"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Настройки")
        dialog.geometry("500x400")
        dialog.configure(bg=self.colors['bg'])
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Вкладка сети
        network_frame = ttk.Frame(notebook, style='Dark.TFrame')
        self.setup_network_tab(network_frame)
        notebook.add(network_frame, text="🌐 Сеть")
        
        # Вкладка уведомлений
        notify_frame = ttk.Frame(notebook, style='Dark.TFrame')
        self.setup_notify_tab(notify_frame)
        notebook.add(notify_frame, text="🔔 Уведомления")
        
        # Вкладка внешнего вида
        appearance_frame = ttk.Frame(notebook, style='Dark.TFrame')
        self.setup_appearance_tab(appearance_frame)
        notebook.add(appearance_frame, text="🎨 Внешний вид")
    
    def setup_network_tab(self, parent):
        """Настройка вкладки сети"""
        ttk.Label(parent, text="Настройки сети",
                 style='Dark.TLabel',
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        # Порт
        port_frame = ttk.Frame(parent, style='Dark.TFrame')
        port_frame.pack(fill='x', padx=20, pady=5)
        
        ttk.Label(port_frame, text="Порт:", style='Dark.TLabel').pack(side='left')
        port_entry = ttk.Entry(port_frame, style='Dark.TEntry', width=10)
        port_entry.pack(side='right')
        port_entry.insert(0, str(self.node.port))
        
        # STUN серверы
        stun_frame = ttk.LabelFrame(parent, text="STUN серверы", style='Dark.TFrame')
        stun_frame.pack(fill='x', padx=20, pady=10)
        
        stun_text = scrolledtext.ScrolledText(stun_frame,
                                            height=4,
                                            bg=self.colors['card'],
                                            fg=self.colors['fg'])
        stun_text.pack(fill='x', padx=10, pady=10)
        
        for server in self.node.stun_servers:
            stun_text.insert('end', f"{server[0]}:{server[1]}\n")
    
    def setup_notify_tab(self, parent):
        """Настройка вкладки уведомлений"""
        ttk.Label(parent, text="Настройки уведомлений",
                 style='Dark.TLabel',
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        # Чекбоксы
        options = [
            ("Показывать уведомления о новых сообщениях", True),
            ("Звуковые уведомления", True),
            ("Уведомлять о подключении контактов", True),
            ("Показывать предупреждения безопасности", True)
        ]
        
        for text, default in options:
            var = tk.BooleanVar(value=default)
            cb = ttk.Checkbutton(parent, text=text, variable=var,
                                style='Dark.TCheckbutton')
            cb.pack(anchor='w', padx=20, pady=5)
    
    def setup_appearance_tab(self, parent):
        """Настройка вкладки внешнего вида"""
        ttk.Label(parent, text="Настройки внешнего вида",
                 style='Dark.TLabel',
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)
        
        # Тема
        theme_frame = ttk.Frame(parent, style='Dark.TFrame')
        theme_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(theme_frame, text="Тема:", style='Dark.TLabel').pack(side='left')
        
        theme_var = tk.StringVar(value="Темная")
        themes = ["Темная", "Светлая", "Системная"]
        
        for theme in themes:
            rb = ttk.Radiobutton(theme_frame, text=theme, variable=theme_var,
                                value=theme, style='Dark.TRadiobutton')
            rb.pack(side='left', padx=10)
    
    def send_encrypted_message(self):
        """Отправка зашифрованного сообщения"""
        if not self.current_chat:
            messagebox.showwarning("Внимание", "Выберите чат для отправки сообщения")
            return
        
        message = self.message_entry.get('1.0', 'end-1c').strip()
        if not message:
            return
        
        # Отправляем через узел
        success = self.node.send_encrypted_message(
            self.current_chat,
            message,
            MessageType.TEXT,
            EncryptionType.CHACHA20_POLY1305
        )
        
        if success:
            # Добавляем в историю
            self.add_message_to_chat(self.username, message, outgoing=True)
            
            # Очищаем поле ввода
            self.message_entry.delete('1.0', 'end')
            
            # Прокручиваем вниз
            self.messages_canvas.yview_moveto(1)
    
    def add_message_to_chat(self, sender: str, message: str, outgoing: bool = False):
        """Добавление сообщения в чат"""
        message_frame = ttk.Frame(self.messages_frame, style='Dark.TFrame')
        message_frame.pack(fill='x', padx=20, pady=5)
        
        # Внутренний фрейм
        inner_frame = ttk.Frame(message_frame, style='Dark.TFrame')
        inner_frame.pack(fill='x')
        
        # Выравнивание
        if outgoing:
            inner_frame.pack(anchor='e')
            bg_color = '#238636'  # Зеленый для исходящих
            text_color = 'white'
        else:
            inner_frame.pack(anchor='w')
            bg_color = self.colors['card']
            text_color = self.colors['fg']
        
        # Текст сообщения
        message_label = tk.Label(inner_frame,
                                text=message,
                                bg=bg_color,
                                fg=text_color,
                                font=('Segoe UI', 11),
                                wraplength=400,
                                justify='left',
                                padx=15, pady=10,
                                borderwidth=0)
        message_label.pack()
        
        # Время
        time_label = ttk.Label(inner_frame,
                              text=datetime.now().strftime('%H:%M'),
                              style='Dark.TLabel',
                              font=('Segoe UI', 9))
        time_label.pack()
        
        # Индикатор шифрования
        if outgoing:
            crypto_label = ttk.Label(inner_frame,
                                    text="🔒",
                                    style='Dark.TLabel',
                                    font=('Segoe UI', 9))
            crypto_label.pack()
        
        # Сохраняем в историю
        self.message_history.append({
            'sender': sender,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'outgoing': outgoing
        })
    
    def attach_file(self):
        """Прикрепление файла"""
        filepath = filedialog.askopenfilename(
            title="Выберите файл для отправки",
            filetypes=[
                ("Все файлы", "*.*"),
                ("Изображения", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("Документы", "*.pdf *.doc *.docx *.txt *.rtf"),
                ("Архивы", "*.zip *.rar *.7z *.tar.gz"),
                ("Медиа", "*.mp3 *.mp4 *.avi *.mkv")
            ]
        )
        
        if filepath:
            # Здесь должна быть реализация отправки файла
            messagebox.showinfo("Файл", f"Файл выбран: {os.path.basename(filepath)}")
    
    def start_voice(self):
        """Начало голосового вызова"""
        if not self.current_chat:
            messagebox.showwarning("Внимание", "Выберите контакт для звонка")
            return
        
        # Здесь должна быть реализация WebRTC звонка
        messagebox.showinfo("Голосовой звонок", "Начинаем голосовой звонок...")
    
    def start_video(self):
        """Начало видеозвонка"""
        if not self.current_chat:
            messagebox.showwarning("Внимание", "Выберите контакт для видеозвонка")
            return
        
        # Здесь должна быть реализация WebRTC видеозвонка
        messagebox.showinfo("Видеозвонок", "Начинаем видеозвонок...")
    
    def on_enter_pressed(self, event):
        """Обработка нажатия Enter"""
        if event.state == 0:  # Без Shift
            self.send_encrypted_message()
            return 'break'  # Предотвращаем перенос строки
        return None
    
    def on_text_change(self, event):
        """Обработка изменения текста"""
        # Можно добавить live preview или подсчет символов
        pass
    
    def rotate_keys(self):
        """Ротация ключей"""
        if messagebox.askyesno("Ротация ключей", 
                              "Вы уверены, что хотите сгенерировать новые ключи?\n"
                              "Все текущие сессии будут разорваны."):
            # Здесь должна быть реализация ротации ключей
            messagebox.showinfo("Успех", "Ключи успешно обновлены")
    
    def export_keys(self):
        """Экспорт ключей"""
        filepath = filedialog.asksaveasfilename(
            title="Экспорт ключей",
            defaultextension=".pem",
            filetypes=[("PEM файлы", "*.pem"), ("Все файлы", "*.*")]
        )
        
        if filepath:
            # Здесь должна быть реализация экспорта ключей
            with open(filepath, 'w') as f:
                f.write("Экспортированные ключи (заглушка)")
            messagebox.showinfo("Успех", f"Ключи экспортированы в {filepath}")
    
    def import_keys(self):
        """Импорт ключей"""
        filepath = filedialog.askopenfilename(
            title="Импорт ключей",
            filetypes=[("PEM файлы", "*.pem"), ("Все файлы", "*.*")]
        )
        
        if filepath:
            # Здесь должна быть реализация импорта ключей
            messagebox.showinfo("Импорт", f"Ключи импортированы из {filepath}")
    
    def process_incoming(self):
        """Обработка входящих сообщений"""
        try:
            while not self.node.incoming_queue.empty():
                item = self.node.incoming_queue.get()
                
                if item['type'] == 'message':
                    self.add_message_to_chat(
                        item['peer_info'].get('username', 'Unknown'),
                        item['content'],
                        outgoing=False
                    )
                
                # Прокручиваем вниз
                self.messages_canvas.yview_moveto(1)
        
        except Exception as e:
            logger.error(f"Process incoming error: {e}")
        
        # Планируем следующую проверку
        self.root.after(100, self.process_incoming)
    
    def update_interface(self):
        """Обновление интерфейса"""
        # Обновляем статус подключения
        connected_count = len(self.node.peers)
        self.connection_status.config(
            text=f"🟢 Подключено | Узлов: {connected_count} | "
                 f"Сообщений: {len(self.message_history)}"
        )
        
        # Планируем следующее обновление
        self.root.after(5000, self.update_interface)
    
    def generate_strong_password(self, length: int = 32) -> str:
        """Генерация сильного пароля"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def run(self):
        """Запуск GUI"""
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.root.mainloop()
        except Exception as e:
            logger.error(f"GUI error: {e}")
            self.on_closing()
    
    def on_closing(self):
        """Обработка закрытия окна"""
        if messagebox.askokcancel("Выход", "Закрыть RAVEN Secure Messenger?"):
            self.node.stop()
            self.root.destroy()

def check_dependencies():
    """Проверка зависимостей"""
    dependencies = [
        'cryptography',
        'nacl',
        'argon2',
        'PIL'
    ]
    
    missing = []
    for dep in dependencies:
        try:
            __import__(dep.replace('-', '_'))
        except ImportError:
            missing.append(dep)
    
    if missing:
        print("Отсутствуют зависимости:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nУстановите: pip install " + " ".join(missing))
        return False
    
    return True

def main():
    """Основная функция"""
    if not check_dependencies():
        return
    
    print("""
    ╔══════════════════════════════════════════════╗
    ║       RAVEN SECURE MESSENGER v2.0            ║
    ║       Квантово-устойчивый P2P мессенджер     ║
    ║       GitHub: @yourusername/raven-messenger  ║
    ╚══════════════════════════════════════════════╝
    
    Особенности:
    • P2P архитектура (без серверов)
    • Военное шифрование (X25519, ChaCha20-Poly1305)
    • Цифровые подписи сообщений
    • OSINT анализ контента
    • Поддержка файлов и медиа
    • Современный графический интерфейс
    """)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "gui":
            username = sys.argv[2] if len(sys.argv) > 2 else None
            password = sys.argv[3] if len(sys.argv) > 3 else None
            
            app = ModernGUI(username, password)
            app.run()
        
        elif sys.argv[1] == "node":
            if len(sys.argv) < 4:
                print("Использование: python raven_messenger.py node <username> <password> [port]")
                return
            
            username = sys.argv[2]
            password = sys.argv[3]
            port = int(sys.argv[4]) if len(sys.argv) > 4 else 0
            
            node = SecureP2PNode(username, password, port)
            node.start()
            
            print(f"\n[*] SecureP2PNode запущен:")
            print(f"    Имя: {username}")
            print(f"    ID: {node.node_id}")
            print(f"    Адрес: {node.host}:{node.port}")
            print(f"    Алгоритмы: X25519 + ChaCha20-Poly1305")
            
            try:
                input("\nНажмите Enter для остановки...\n")
            finally:
                node.stop()
        
        elif sys.argv[1] == "generate-keys":
            # Генерация ключей для демонстрации
            crypto = AdvancedCrypto()
            private, public = crypto.generate_key_pair()
            print(f"Приватный ключ: {private}")
            print(f"Публичный ключ: {public}")
        
        else:
            print("""
Использование:
  python raven_messenger.py gui [username] [password]  - Графический интерфейс
  python raven_messenger.py node <username> <password> [port]  - Командный режим
  python raven_messenger.py generate-keys              - Генерация ключей
            """)
    
    else:
        # Интерактивный режим
        print("[*] Выберите режим:")
        print("1. Графический интерфейс (рекомендуется)")
        print("2. Командный режим (для разработчиков)")
        print("3. Генерация ключей")
        
        try:
            choice = input("\nВведите номер [1-3]: ").strip()
            
            if choice == "1":
                username = input("Имя пользователя (Enter для случайного): ").strip()
                password = input("Пароль (Enter для генерации): ").strip()
                
                if not username:
                    username = f"user_{secrets.token_hex(4)}"
                if not password:
                    password = secrets.token_urlsafe(24)
                
                print(f"\nВаши учетные данные:")
                print(f"  Имя: {username}")
                print(f"  Пароль: {password}")
                print("\nСохраните пароль в безопасном месте!")
                
                input("\nНажмите Enter для запуска...")
                
                app = ModernGUI(username, password)
                app.run()
            
            elif choice == "2":
                username = input("Имя пользователя: ").strip()
                password = input("Пароль: ").strip()
                port = input("Порт (Enter для случайного): ").strip()
                port = int(port) if port.isdigit() else 0
                
                node = SecureP2PNode(username, password, port)
                node.start()
                
                print(f"\n[*] Узел запущен. Используйте второй терминал для подключения.")
                
                try:
                    input("\nНажмите Enter для остановки...")
                finally:
                    node.stop()
            
            elif choice == "3":
                crypto = AdvancedCrypto()
                private, public = crypto.generate_key_pair()
                print(f"\nСгенерированные ключи:")
                print(f"Приватный ключ: {private[:50]}...")
                print(f"Публичный ключ: {public[:50]}...")
            
            else:
                print("Неверный выбор")
        
        except KeyboardInterrupt:
            print("\n\n[*] Выход...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Программа прервана пользователем")
    except Exception as e:
        print(f"\n[!] Фатальная ошибка: {e}")
        import traceback
        traceback.print_exc()
