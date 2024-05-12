import socket
import base64
import json
import struct
from json import JSONDecodeError

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class voip_server_class:
    def __init__(self):
        """
        Initialize the server socket and other variables.
        the constructor function
        returns None
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(('0.0.0.0', 12000))
        self.connected_users = {}
        self.active_calls = {}

    def run(self):
        """
        the main loop of the server
        :return: None
        """
        while True:
            try:
                data, addr = self.server_socket.recvfrom(1024)
                print("recieved udp data!\nrecieved udp data!\nrecieved udp data!\nrecieved udp data!\nrecieved udp data!\n")
                print(data)
                print(
                    "recieved udp data!\nrecieved udp data!\nrecieved udp data!\nrecieved udp data!\nrecieved udp data!\n")
                temp_data = data
                data = json.loads(data)
                user_token_hash = data["token_hash"]
            except JSONDecodeError:
                print("JSONDecodeError")
                continue

    @staticmethod
    def decrypt_from_json_string(json_data_string, aes_key):
        """
        decrypt the json data string using the aes key
        :param json_data_string: the json data string to decode
        :param aes_key: the aes key to use
        :return: the decrypted data
        """
        json_data = json.loads(json_data_string)
        iv = base64.b64decode(json_data["aes_iv"])
        auth_tag = base64.b64decode(json_data["auth_tag"])
        encrypted = base64.b64decode(json_data["encrypted_data"])
        cipher_object = AES.new(aes_key, mode=AES.MODE_GCM, nonce=iv)
        decryptedtext = cipher_object.decrypt(encrypted)
        cipher_object.verify(auth_tag)
        return decryptedtext.decode()

    @staticmethod
    def encrypt_to_json_string(data, aes_key):
        """
        encrypt the data using the aes key into the json data string
        :param data: the data to encrypt
        :param aes_key: the aes key to use
        :return: the encrypted json data string
        """
        iv = get_random_bytes(12)
        cipher_object = AES.new(aes_key, mode=AES.MODE_GCM, nonce=iv)
        ciphertext, auth_tag = cipher_object.encrypt_and_digest(data)
        print(auth_tag)
        json_data = {
            "aes_iv": base64.b64encode(iv).decode(),
            "auth_tag": base64.b64encode(auth_tag).decode(),
            "encrypted_data": base64.b64encode(ciphertext).decode()
        }
        return json.dumps(json_data)

