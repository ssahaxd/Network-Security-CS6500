import os
import socket
import sys
import threading
import logging
from handler import handle_client 


def exit_with_help(error=''):
    print("""\
Usage: kdc.py [options]

options:
    -p : portid 
    -o : outfilename
    -f : pwdfile
 """)
    print(error)
    sys.exit(1)


# Arguments to be read from command line
args = [('p', 'p', 'p'),
        ('o', 'o', 'o'), ("f", "f", "f")]

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
        if options[i] == '-p':
            i = i + 1
            PORT = int(options[i])
        elif options[i] == '-o':
            i = i + 1
            outfile = options[i]
        elif options[i] == '-f':
            i = i + 1
            pwdfile = options[i]
        else:
            exit_with_help('Error: Unknown Argument! (' + options[i] + ')')
        i = i + 1

# ----------------------------------------
# Setting up logging
# ----------------------------------------

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] - %(message)s',
                    datefmt='%Y-%m-%d %I:%M %p',    
                    handlers=[
                        logging.FileHandler(outfile),
                        logging.StreamHandler(sys.stdout)
                    ])

# ----------------------------------------
# Server code starts Here
# ----------------------------------------

SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)


def start():
    server.listen()
    logging.info(f"Server is listening on {ADDRESS[0]}:{ADDRESS[1]}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client , args=(conn, addr, pwdfile))
        thread.start()


logging.info(f"Starting server at {ADDRESS[0]}:{ADDRESS[1]}")
start()


