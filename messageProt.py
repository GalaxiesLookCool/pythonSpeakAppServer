import struct


class messageProt:

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
        if (len(string) > 20):
            string = string [:21]
        else:
            string = (20 - len(string) )* "0" + string


    @staticmethod
    def send_msg(sock, msg : str|bytes | bytearray, seq_number : int = 0):
        """
        sends a message to the socket in the correct format
        :param sock: socket to send into
        :param msg:  msg in string or bytes
        :param seq_number: sequence number in int
        :return: none
        """
        if (type(msg) is str):
            msg = msg.encode()
        msg = messageProt.seqBinary(seq_number) + msg
        msg = messageProt.sizeBinary(msg) + msg
        #print(f"size is {len(msg) - 4}")
        # Prefix each message with a 4-byte length (BIG order)
        # and prefix each message with a 4-byte seq number
        #msg = struct.pack('>I', len(msg)) + seq_number + msg
        sock.sendall(msg)

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


    @staticmethod
    def recv_msg(sock) -> (str, int):
        """
        gets a message from the socket in the format. returns msg and seq
        :param sock: socket to receive from
        :return:  tuple of message and seq number
        """
        # Read message length and unpack it into an integer
        raw_msglen = messageProt.recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = messageProt.getSizeFromBinary(raw_msglen)
        # Read the message data
        dataFull = messageProt.recvall(sock, msglen)
        seqRaw = dataFull[:4]
        #print(f"raw seq is {seqRaw}")
        seqNumber = messageProt.getSeqBinary(seqRaw)
        #print(f" non raw seq is {seqNumber}")
        dataFull = dataFull[4:]
        return dataFull.decode(), seqNumber