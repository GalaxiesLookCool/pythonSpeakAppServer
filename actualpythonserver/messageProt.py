import base64
import json
import struct
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class messageProt:

    def __init__(self, sock):
        self.sock = sock
        self.aes_used = False
        self.aes_key = None

    def get_ip(self):
        """
        gets the ip of the socket of the object
        :return: the ip of the socket of the object
        """
        return self.sock.getpeername()[0]


    keyPair = RSA.generate(3072)
    encryptor = PKCS1_OAEP.new(keyPair.publickey())
    decryptor = PKCS1_OAEP.new(keyPair)

    def set_aes_key(self, key):
        """
        sets the aes key of the object
        :param key: the aes key
        :return: none
        """
        self.aes_key = key
        self.aes_used = True
        print("aes key is::::")
        print(self.aes_key)
        print("aes key is:::::")

    def decrypt_from_json_string(self, json_data_string):
        """
        decrypts the json data string (has to be in the correct format)
        :param json_data_string: the string of a json.dumps function of the data to be decrypted
        :return: the decrypted data
        """
        json_data = json.loads(json_data_string)
        iv = base64.b64decode(json_data["aes_iv"])
        auth_tag = base64.b64decode(json_data["auth_tag"])
        encrypted = base64.b64decode(json_data["encrypted_data"])
        cipher_object = AES.new(key=self.aes_key, mode=AES.MODE_GCM, nonce=iv)
        decryptedtext = cipher_object.decrypt(encrypted)
        cipher_object.verify(auth_tag)
        return decryptedtext.decode()

    def encrypt_to_json_string(self, data):
        """
        encrypts the data and returns the json string
        :param data: the data to be encrypted
        :return: the json string of the encrypted data
        """
        iv = get_random_bytes(12)
        cipher_object = AES.new(key=self.aes_key, mode=AES.MODE_GCM, nonce=iv)
        ciphertext, auth_tag = cipher_object.encrypt_and_digest(data)
        print(auth_tag)
        json_data = {
            "aes_iv": base64.b64encode(iv).decode(),
            "auth_tag": base64.b64encode(auth_tag).decode(),
            "encrypted_data": base64.b64encode(ciphertext).decode()
        }
        return json.dumps(json_data)

    @staticmethod
    def sizeBinary(msg):
        """
        get the size of the message in bytes and return it as a 4 byte binary
        :param msg: message string
        :return: binary of the message in binary
        """
        length = len(msg)
        return length.to_bytes(4 , "big")

    @staticmethod
    def getSizeFromBinary(fourBinary):
        """
        gets the size of the message from the binary
        :param fourBinary: binary of 4 bytes
        :return: message size in it
        """
        return int.from_bytes(fourBinary, "big")

    @staticmethod
    def seqBinary(seqNum=0):
        """
        gets the binary of the sequence number
        :param seqNum: sequence number
        :return: binary of the sequence number
        """
        #print(seqNum)
        return seqNum.to_bytes(4, "big")

    @staticmethod
    def getSeqBinary(fourBinary):
        """
        gets the sequence number from the binary
        :param fourBinary:
        :return: the number in the binary repr of the sequence number
        """
        return  int.from_bytes(fourBinary, "big")

    @staticmethod
    def make_string_long(string, length):
        """
        fits string into given length (shortens or pads it)
        :param string:
        :param length:
        :return:
        """
        if (len(string) > length):
            string = string [:length + 1]
        else:
            string = (length - len(string) )* "0" + string


    def send_msg(self, msg : str|bytes | bytearray, seq_number : int = 0):
        """
        sends a message to the socket in the correct format
        :param sock: socket to send into
        :param msg:  msg in string or bytes
        :param seq_number: sequence number in int
        :return: none
        """
        print("sending msg in message prot")
        print(msg)
        if (type(msg) is str):
            msg = msg.encode()
        if self.aes_used:
            msg = self.encrypt_to_json_string(msg).encode()
        msg = messageProt.seqBinary(seq_number) + msg
        msg = messageProt.sizeBinary(msg) + msg
        #print(f"size is {len(msg) - 4}")
        # Prefix each message with a 4-byte length (BIG order)
        # and prefix each message with a 4-byte seq number
        #msg = struct.pack('>I', len(msg)) + seq_number + msg
        self.sock.sendall(msg)
        print("sent msg")

    @staticmethod
    def recvall(sock, n):
        """
        gets n bytes or less from the socket
        :param sock: socket to read from
        :param n: number of bytes
        :return: none if EOF or n bytes
        """
        # Helper function to recv n bytes or return None if EOF is hit
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data


    def recv_msg(self) -> (str, int):
        """
        gets a message from the socket in the format. returns msg and seq
        :param sock: socket to receive from
        :return:  tuple of message and seq number
        """
        # Read message length and unpack it into an integer
        raw_msglen = messageProt.recvall(self.sock, 4)
        if not raw_msglen:
            return None
        msglen = messageProt.getSizeFromBinary(raw_msglen)
        # Read the message data
        dataFull = messageProt.recvall(self.sock, msglen)
        seqRaw = dataFull[:4]
        #print(f"raw seq is {seqRaw}")
        seqNumber = messageProt.getSeqBinary(seqRaw)
        #print(f" non raw seq is {seqNumber}")
        dataFull = dataFull[4:]
        print(dataFull)
        print("decoded is ")
        return self.decrypt_from_json_string(dataFull.decode()) if self.aes_used else dataFull.decode(), seqNumber
