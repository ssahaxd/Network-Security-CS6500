import socket
import threading


class CreateSocket():
    HEADER = 64

    def __init__(self, server_ip, server_port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((server_ip, server_port))
        self.server.listen()
        

    def handle_accept(self):
        self.conn, self.addr = self.server.accept()
        return [self.send, self.on_read, self.addr]

    def fileno(self):
        return self.server.fileno()

    def on_read(self):
        '''
        return type : binary
        '''
        msg_length = self.conn.recv(self.HEADER).decode("utf-8")
        if msg_length:
            msg_length = int(msg_length)
            msg = b''
            while msg_length:
                if msg_length < 65536:
                    msg += self.conn.recv(msg_length)
                    msg_length = 0
                else:
                    msg += self.conn.recv(65536)
                    msg_length -= 65536

            if msg == b'!DISCONNECT':
                self.conn.close()
                return 
            else:
                return msg
        else:
            return b''

    def send(self, msg):
        try:
            message = msg.encode("utf-8")
        except:
            message = msg

        # send message length first
        msg_length = len(message)
        msg_length = str(msg_length).encode("utf-8")
        msg_length += b' ' * (self.HEADER - len(msg_length))
        self.conn.send(msg_length)
        self.conn.send(message)

    def __del__(self):
        self.server.close()





class Connection():
    HEADER = 64

    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((server_ip, server_port))
    

    def fileno(self):
        return self.conn.fileno()

    def on_read(self):
        '''
        return type : binary
        '''
        msg_length = self.conn.recv(self.HEADER).decode("utf-8")
        if msg_length:
            msg_length = int(msg_length)
            msg = self.conn.recv(msg_length)
            if msg == b'!DISCONNECT':
                self.conn.close()
                return 
            else:
                return msg
        else:
            return b''

    def send(self, msg):
        try:
            message = msg.encode("utf-8")
        except:
            message = msg

        # send message length first
        msg_length = len(message)
        msg_length = str(msg_length).encode("utf-8")
        msg_length += b' ' * (self.HEADER - len(msg_length))
        self.conn.send(msg_length)
        self.conn.sendall(message)

    def disconnect(self):
        if self.conn:
            self.send('!DISCONNECT')
            self.conn.close()

