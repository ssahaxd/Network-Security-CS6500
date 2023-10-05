 
import sys
from os import path
from Crypto.PublicKey import RSA

def print_progress(progress, total):
    sys.stdout.flush()
    sys.stdout.write("\rProcessing: %d%%" % (100 * progress / total))


number_of_args = len(sys.argv)
if number_of_args != 3:
    print("Usage: CreateKeys.py <user_list> <RSA_key_size>")
    exit(1)
else:
    user_list = sys.argv[1]
    rsa_key_size = int(sys.argv[2]) if int(sys.argv[2]) in [2048, 1024] else 0
    if rsa_key_size != 0:
        try:
            with open(user_list, 'r') as f:
                users = f.readlines()
                print_progress(0,len(users)-1)
                
                for i in range(len(users)):
                    with open(f'keys/{users[i][:-1]}_priv.PEM','wb') as kf:
                        key = RSA.generate(rsa_key_size)
                        kf.write(key.export_key('PEM'))
                    with open(f'keys/{users[i][:-1]}_pub.PEM','wb') as kf:
                        kf.write(key.publickey().export_key('PEM'))
                    print_progress(i,len(users)-1)
        except NameError:
            print(NameError)

    else:
        print("Not a valid Key length")
        print("Usage: CreateKeys.py <user_list> <RSA_key_size 2048|1024>")
        exit(1)
        

    
 
