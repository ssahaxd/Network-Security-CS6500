import os
import sys
import util
import time
import socket
import random
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
import connection


# ./client -n myname -m S -o othername -i inputfile -a kdcip -p kdcport
# ./client -n myname -m R -s outenc -d outfile -a kdcip -p kdcport

def exit_with_help(error=''):
    print("""\
Usage: client.py [options]

options:
    -n : client name 
    -m : [S]ender/[R]eceiver
    -o : receiver’s name
    -i : input file
    -a : kdc ip
    -p : kdc port
    -s : received encrypted file
    -d : decrypted received file

 """)
    print(error)
    sys.exit(1)


# Arguments to be read from command line
args = [('n', 'n', 'n'), ('m', 'm', 'm'),
        ('a', 'a', 'a'), ("p", "p", "p"), ]

# Checking if all variables are/will be set
for var, env, arg in args:
    if not '-' + arg in sys.argv:
        vars()[var] = os.getenv(env)
        if vars()[var] == None:
            exit_with_help('Error: Environmental Variables or Argument' +
                           ' insufficiently set! ($' + env + ' / "-' + arg + '")')

# Read parameters from command line call
if len(sys.argv) != 0:
    i = 0
    options = sys.argv[1:]
    # iterate through parameters
    while i < len(options):
        if options[i] == '-n':
            i = i + 1
            client_name = options[i]
        elif options[i] == '-m':
            i = i + 1
            client_type = options[i]
        elif client_type == "S" and options[i] == '-o':
            i = i + 1
            recvr_name = options[i]
        elif client_type == "S" and options[i] == '-i':
            i = i + 1
            input_file = options[i]
        elif client_type == "R" and options[i] == '-s':
            i = i + 1
            enc_file = options[i]
        elif client_type == "R" and options[i] == '-d':
            i = i + 1
            dec_file = options[i]
        elif options[i] == '-p':
            i = i + 1
            SERVER_PORT = int(options[i])
        elif options[i] == '-a':
            i = i + 1
            SERVER_IP = options[i]
        else:
            exit_with_help('Error: Unknown Argument! (' + options[i] + ')')
        i = i + 1


# ----------------------------------------
# Client functions
# ----------------------------------------


def register(CLIENT_IP, CLIENT_PORT, client_name):
    master_secret = b64encode(get_random_bytes(12)).decode()
    reg_msg = f"301|{CLIENT_IP}|{CLIENT_PORT}|{master_secret}|{client_name}"
    conn.send(reg_msg)
    return master_secret


def dec_session_key(data): 
    data = b64decode(data)
    enc_key = master_key(master_secret, client_name)
    data = util.AES_decrypt_ASCII(data, enc_key)
    return data


def extract_session_key(data, client_name, master_secret):
    data = data.split("|")
    if(data[0]) == "306":
        sender_data = data[1]
        recvr_data = data[2]
        session_key, _, recvr_name, nonce, recvr_ip, recvr_port = dec_session_key(
            sender_data).split("|")
        return [nonce, session_key, recvr_data, recvr_name, recvr_ip, recvr_port]


def master_key(master_secret, client_name):
    key_phrase = master_secret+client_name
    return util.get_key(key_phrase.encode(FORMAT))


def req_session_key(sender_name, recvr_name, master_secret):
    nonce = random.randint(0, 9999)
    reg_msg = f"{sender_name}|{recvr_name}|{nonce}".encode(FORMAT)
    enc_key = master_key(master_secret, sender_name)
    enc_msg = util.AES_encrypt(reg_msg, enc_key)
    enc_msg_b64 = b64encode(enc_msg).decode(FORMAT)
    reg_payload = f"305|{enc_msg_b64}|{sender_name}"
    conn.send(reg_payload)


def listen_for_sender(SERVER, PORT):
    ADDRESS = (SERVER, PORT)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDRESS)
    server.listen()

    conn, addr = server.accept()
    print(f"Connected: {addr}")
    print(conn.recv(2048).decode(FORMAT))
    session_key = dec_session_key(conn.recv(2048).decode(FORMAT))
    print(session_key)
    session_key = session_key.split("|")[0]
    session_key = b64decode(session_key)
    print(session_key)
    print(conn.recv(64).decode(FORMAT))
    data = conn.recv(2048)
    print(data)
    print(util.AES_decrypt_ASCII(data, session_key))
    conn.close()


# ----------------------------------------
# Client code starts Here
# ----------------------------------------


HEADER = 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

CLIENT_PORT = random.randint(2000, 9999)
CLIENT_IP = socket.gethostbyname(socket.gethostname())
if client_type == "R":
    CLIENT_IP = "127.0.35.50"
server_address = (SERVER_IP, SERVER_PORT)
client_address = (CLIENT_IP, CLIENT_PORT)


conn = connection.Connection(SERVER_IP, SERVER_PORT)

print("Contacting to KDC...")
master_secret = register(
    CLIENT_IP=CLIENT_IP, CLIENT_PORT=CLIENT_PORT, client_name=client_name)

print(f"Registered, :{conn.on_read()}")



if client_type == "S":
    print("Sleeps for 15 seconds...")
    time.sleep(2)
    print("Requesting for session key...")
    req_session_key(sender_name=client_name,
                    recvr_name=recvr_name, master_secret=master_secret)

    nonce, session_key, recvr_data, recvr_name, recvr_ip, recvr_port = extract_session_key(
        conn.on_read().decode(FORMAT), client_name, master_secret)
    session_key = b64decode(session_key)
    print(f"session key received: {session_key}")
    conn.disconnect()
    print("Disconnected from KDC...")

    try:
        print(f"Connecting {recvr_name} @ {recvr_ip}:{recvr_port}")
        conn = connection.Connection(recvr_ip, int(recvr_port))
        print(f"Sending {input_file} to {recvr_name}")
        # 309| E_KB[ Ks | IDA | IDB | Nonce1 | IPAddrA | PortNoA] | IDA
        data = f"309|{recvr_data}|{client_name}"
        conn.send(data)
        with open(input_file, "rb") as fi:
            data = util.AES_encrypt(fi.read(), session_key)
            print(f"enc data size: {len(data)} Bytes")
            conn.send(data)
        print("File sent, Disconnecting!")
        conn.disconnect()
        print("Disconnected!")
    except Exception as e:
        print(e)
    finally:
        exit()

else:
    print("Disconnected from KDC...")
    conn.disconnect()

    try:
        print(f"Stated listining @ {CLIENT_IP}:{CLIENT_PORT}")
        server = connection.CreateSocket(CLIENT_IP, CLIENT_PORT)
        send, recv, addr = server.handle_accept()
        print(f"{addr} got connected!")
        session_key = recv()
        session_key = session_key.decode("utf-8").split("|")[1]
        session_key = dec_session_key(session_key)
        # Ks | IDA | IDB | Nonce1 | IPAddrA | PortNoA
        session_key, sender_name = session_key.split("|")[0:2]
        session_key = b64decode(session_key)
        print(f"Received session_key: {session_key} from {sender_name}")

        print(f"Waiting for file...")
        data = recv()
        
        print(f"Received Data: {len(data)} Bytes ")
        with open(enc_file, "wb") as fo:
            fo.write(data)
            print(f"Encrypted data written to {enc_file}")

        data = util.AES_decrypt(data, session_key)

        with open(dec_file, "wb") as fo:
            fo.write(data)
            print(f"Decrypted data written to {dec_file}")

        print("[x] Done! Closing Server..")


    except Exception as e:
        print(e)
    finally:
        exit()

