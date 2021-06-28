# Ehud Wasserman, 315005090, Yuval Tal, 311127120

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from threading import Thread
from threading import Lock
from random import shuffle
import time
import socket


##########################
# common code to mix.py, sender.py, recevier.py:

class Asymmetric:
# Class for Asymmetric encryption. raises exception if keys invalids.

    @staticmethod
    def load_RSA_keys(private_key: str = None, public_key: str = None):
    # Return (sk,pk) that are objects (or None) corrosponding to the str(pem) that given as params.

        if private_key != None:
            # load private key object from str
            private_key = load_pem_private_key(private_key.encode(), None, default_backend())
            public_key = private_key.public_key()
        elif public_key != None:
            public_key = load_pem_public_key(public_key.encode(), default_backend())

        return private_key, public_key

    @staticmethod
    def encrypt(plaintext: bytes, public_key):
    # Using public key, get bytes and return bytes that are the encryption(with padding).

        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt(ciphertext: bytes, private_key):
    # Decrypt cipher bytes to get the original plaintext(bytes)

        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class Symmetric:
# Class to symetric encryption. raises exception if key invalid.

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes):
    # get bytes and key. retrun their encryption(bytes). raises error if key is invalid.

        cipher = Fernet(key)
        return cipher.encrypt(plaintext)

    @staticmethod
    def decrypt(token: bytes, key: bytes):
    # get bytes and key. retrun their decryption(bytes). raises error if key is invalid.

        cipher = Fernet(key)
        return cipher.decrypt(token)

    @staticmethod
    def generate_key(password: bytes, salt: bytes):
    # generate key from password and salt.

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))


# variable to avoid multi-threads collision
curr_thread_lock = Lock()


def thread_safe(func, params: tuple = ()):
# execute func with params without collision of threads.

    # if func is code block then all program will be block
    global curr_thread_lock
    curr_thread_lock.acquire()
    result = func(*params)
    curr_thread_lock.release()
    return result


def interval(func, params: tuple, should_stop_callable, delay):
# execute func with params every $delay seconds, in seperated thread, while not should_stop_callable()

    # func should use thread_safe() if needed
    def loop():
        while not should_stop_callable():
            start_time = time.mktime(time.localtime())
            func(*params)
            if not should_stop_callable():
                time_passed = time.mktime(time.localtime()) - start_time
                time.sleep(max(0, delay - time_passed))

    t = Thread(target=loop, args=())
    t.start()
    return t



class Packet:
# class that represented packet with methods to pack / unpack (+/- layer) it

    opened_target_sockets = {} # current private sockets that are opened
                               # [in truth, we close every each after the msg sent]
    ROUND_TIME = 60  # in seconds

    def __init__(self, ip_dest: str = "", port_dest: str = "0", app_data: bytes = b"", sk: bytes = None,
                 round_to_send=0):
    # constructor, make also symetric encryption if sk is given

        self.__dest = (ip_dest, int(port_dest))
        self.round_to_send = round_to_send
        if sk:
            app_data = Symmetric.encrypt(app_data, sk)
        self.__app_data = app_data

    @staticmethod
    def bytes_to_dest(b):
    # convert 4+2 bytes to tuple(ip,port)

        ints = []
        for byte in b:
            ints.append(byte)
        # port = 256*ints[4] + ints[5]
        ints[4] *= 256
        ints[4] += ints[5]
        ip_dest = ".".join([str(s) for s in ints[:4]])
        port_dest = str(ints[4])
        return ip_dest, port_dest

    @staticmethod
    def dest_to_bytes(dest_ip: str, dest_port: str):
    # convert tuple(ip,port) to 4+2 bytes

        ints = [int(i) for i in dest_ip.split(".")]
        dest_port = int(dest_port)
        # convert the port to 2 bytes:
        ints.append(int(dest_port / 256))
        ints.append(int(dest_port % 256))
        return bytes(ints)

    def pack(self, new_ip_dest: str, new_port_dest: str, pk_dest):
    # gather this package data (ip-dest+port-dest+app_data) and encrypt it by public key (asymmetric)
    # as new app_data of new package
    # which will have new dest(ip+port), and return that new Packet

        ip, port = self.__dest
        port = str(port)
        app_data = Packet.dest_to_bytes(ip, port) + self.__app_data
        app_data = Asymmetric.encrypt(app_data, pk_dest)
        return Packet(new_ip_dest, new_port_dest, app_data, round_to_send=self.round_to_send)

    def unpack(self, sk):
    # get the "inner" packet from this packet, meaning, get packet from the app_data, after decryption by sk(asymmetric)

        plaintext = Asymmetric.decrypt(self.__app_data, sk)
        ip, port = Packet.bytes_to_dest(plaintext[:6])
        app_data = plaintext[6:]
        return Packet(ip, port, app_data, round_to_send=self.round_to_send)

    def get_data(self, sk=None):
    # decrypt the app_data by sk (symetric) and return the result
        if sk:
            return Symmetric.decrypt(self.__app_data, sk)
        return self.__app_data

    @staticmethod
    def __get_target_socket(dest):
    # get connected socket (private/client tcp-socket) to dest[tuple of ip(str),port(int)], connect if needed
        try:
            if dest not in Packet.opened_target_sockets:
                dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_socket.connect(dest)
                Packet.opened_target_sockets[dest] = dest_socket
            return Packet.opened_target_sockets[dest]
        except:
            Packet.__del_target_socket(dest)
            return None

    @staticmethod
    def __del_target_socket(dest):
    # close open socket (private/client tcp-socket) to dest[tuple of ip(str),port(int)]
    # and remove it from opened_target_sockets
        if dest in Packet.opened_target_sockets:
            try:
                Packet.opened_target_sockets[dest].close()
            except:
                pass
            del Packet.opened_target_sockets[dest]

    def send(self, current_round=None):
    # send this package to its dest, if it's suitable round. current_round=None, meaning send it Now.
    # return true if the package was sent, false otherwise.

        if current_round is not None and current_round < self.round_to_send:
            return False
        try:
            client = Packet.__get_target_socket(self.__dest)
            client.send(self.__app_data)
            Packet.__del_target_socket(self.__dest)
            return True
        except:
            Packet.__del_target_socket(self.__dest)
            return False



def send_packets(packets, current_round=[None]):
# send all package in param packets that are in current_round[0] round, current_round=[None] meaning send all.
# packets param (list) is affected and packages that sent are remived from it. current_round[0] is also increased.

    shuffle(packets)
    next_time = []
    # notice sending is one-by-one, in this thread:
    for p in packets:
        if not p.send(current_round[0]):
            next_time.append(p)
    packets.clear()
    packets.extend(next_time)
    if current_round[0] != None:
        current_round[0] += 1


def send_packets_thread_safe(packets, current_round=[None]):
    thread_safe(send_packets, (packets, current_round))


queue_out = [] # list of packages that should be sent

threads = [] # current threads in this program (except for main thread)
stop_all_threads = False # tell all threads to stop as soon as they are able to

### python3 mix.py Y          where Y is mix-server number

from sys import argv

# load secret_key from skY.pem
mix_num = int(argv[1])
secret_key = None
with open("sk" + str(mix_num) + ".pem") as file:
    secret_key, _ = Asymmetric.load_RSA_keys(private_key=file.read())

# bind tcp server-socket to port that mentioned in ips.txt for this mix-server
server_port = None
with open("ips.txt") as file:
    line = file.readlines()[mix_num - 1]
    server_port = line.split(" ")[1]

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', int(server_port)))
server.listen(20)


def get_package_to_send(client_socket):
# from opened client-tcp socket, read all bytes and retrun Packet from the data. return None if exception occured
    global secret_key
    global mix_num
    try:
        ciphertext = b""
        while True:
            client_socket.settimeout(2)
            addition_ciphertext = client_socket.recv(1)
            client_socket.settimeout(None)
            ciphertext += addition_ciphertext
            if not addition_ciphertext:
                break
        # create and return Packet from msg
        return Packet(app_data=ciphertext).unpack(secret_key)
    except:
        # error raised on RST from client or timeout
        return None



def handle_client(client_socket, socket_alive):
# from opened client-tcp socket, read data to make from it package+dest and append it to the queue_out,
# to send it in future

    global queue_out
    packet = get_package_to_send(client_socket)
    socket_alive[0] = False
    try:
        client_socket.close()
    except:
        pass
    # only if no error occured in get_package_to_send()
    if packet is not None:
        thread_safe(lambda: queue_out.append(packet))


def accept_client(server_socket):
# from SERVER-tcp socket, (bound to port from all interfaces), accept_client and send it to handle_client
    client_socket, client_address = server.accept()
    # it doesn't matter here the socket_alive=[True] or Packet.ROUND_TIME/100
    # because we get only 1 msg per connection in handle_client()
    socket_alive = [True]
    threads.append(
        interval(handle_client, (client_socket, socket_alive), lambda: stop_all_threads or not socket_alive[0],
                 Packet.ROUND_TIME / 100))


# every Packet.ROUND_TIME, send packets from queue_out
threads.append(interval(send_packets_thread_safe, (queue_out,), lambda: stop_all_threads, Packet.ROUND_TIME / 1))

# threads changes only within accept_client()
while True:
    try:
        accept_client(server)
    except (KeyboardInterrupt, EOFError):
        stop_all_threads = True
        break
    except:
        stop_all_threads = True
        break

# threads changed only within accept_client() which no longer called if we here.
for t in threads:
    t.join()

for s in Packet.opened_target_sockets:
    try:
        s.close()
    except:
        pass

try:
    server.close()
except:
    pass
