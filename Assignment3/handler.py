import os
import socket
import sys
import threading
import logging
import json
import util
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes


HEADER = 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
args = {"301": "REG_REQ", "305": "KEY_REQ"}
pwdfile = ""


def send(conn, msg):
    try:
        message = msg.encode("utf-8")
    except:
        message = msg

    # send message length first
    msg_length = len(message)
    msg_length = str(msg_length).encode("utf-8")
    msg_length += b' ' * (HEADER - len(msg_length))
    conn.send(msg_length)
    conn.sendall(message)


def handle_message(conn, msg):
    msg_type = msg.split("|")[0]
    if msg_type not in args.keys():
        logging.info(f"[ERROR] - Received an invalid message type {msg_type}")
    else:
        if args[msg_type] == args["301"]:
            register_client(msg)
            # | 302| ClientName|
            # trying new send
            # conn.send(f"{302}|{msg.split('|')[-1]}".encode(FORMAT))
            send(conn,f"{302}|{msg.split('|')[-1]}".encode(FORMAT))
        elif args[msg_type] == args["305"]:
            # conn.send(handle_key_req(msg).encode(FORMAT))
            send(conn,handle_key_req(msg).encode(FORMAT))


def handle_key_req(msg):
    # 305| E_KA[ IDA|| IDB|| Nonce1] | IDA
    msg = msg.split("|")
    reg_msg_b64 = msg[1]
    client_name = msg[2]
    reg_msg = b64decode(reg_msg_b64.encode(FORMAT))

    with open(pwdfile, 'r') as fo:
        data = json.load(fo)
        master_secret = data[client_name]["passphrase"]
        key_phrase = master_secret+client_name
        enc_key = util.get_key(key_phrase.encode(FORMAT))

    dec_msg = util.AES_decrypt_ASCII(reg_msg, enc_key)
    sender, receiver, nonce = dec_msg.split("|")

    with open(pwdfile, 'r') as fo:
        data = json.load(fo)
        SENDER_IP = data[client_name]["ip"]
        SENDER_PORT = data[client_name]["port"]
        RCVR_IP = data[receiver]["ip"]
        RCVR_PORT = data[receiver]["port"]
        RCVR_master_secret = data[receiver]["passphrase"]
        RCVR_key_phrase = RCVR_master_secret+receiver
        RCVR_enc_key = util.get_key(RCVR_key_phrase.encode(FORMAT))

    # Sender
    # 306| E_KA[ Ks || IDA || IDB || Nonce1 || IPAddrB || PortNoB ||
    # E_KB[ Ks || IDA || IDB || Nonce1 || IPAddrA || PortNoA] ] |

    Ks = get_random_bytes(16)
    Ks = b64encode(Ks).decode(FORMAT)

    sender_res = f"{Ks}|{sender}|{receiver}|{nonce}|{RCVR_IP}|{RCVR_PORT}".encode(
        FORMAT)
    rcvr_res = f"{Ks}|{sender}|{receiver}|{nonce}|{SENDER_IP}|{SENDER_PORT}".encode(
        FORMAT)

    sender_enc_res = util.AES_encrypt(sender_res, enc_key)
    sender_enc_res_b64 = b64encode(sender_enc_res).decode(FORMAT)
    rcvr_enc_res = util.AES_encrypt(rcvr_res, RCVR_enc_key)
    rcvr_enc_msg_b64 = b64encode(rcvr_enc_res).decode(FORMAT)
    payload = f"306|{sender_enc_res_b64}|{rcvr_enc_msg_b64}"
    return payload


def register_client(msg):
    # :alice:10.4.5.11:35678:ABCDEFabcdef123456789=:
    client_data = {}
    msg = msg.split("|")
    client_data[msg[-1]] = {
        "ip": msg[1],
        "port": msg[2],
        "passphrase": msg[3]
    }

    if os.stat(pwdfile).st_size == 0:
        with open(pwdfile, 'w') as fo:
            json.dump(client_data, fo)
    else:
        with open(pwdfile, 'r') as fo:
            data = json.load(fo)
            data.update(client_data)
        with open(pwdfile, 'w') as fo:
            json.dump(data, fo)


def handle_client(conn, addr, _pwdfile):
    global pwdfile
    pwdfile = _pwdfile
    logging.info(f"New connection : {addr[0]}:{addr[1]} connected.")
    connected = True

    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == DISCONNECT_MESSAGE:
                connected = False
                break

            logging.info(f"New message from {addr[0]}:{addr[1]} - {msg}")
            handle_message(conn, msg)

    logging.info(f"Client Disconnected: {addr[0]}:{addr[1]}")
    conn.close()
