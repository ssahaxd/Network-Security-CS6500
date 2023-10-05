#!/bin/sh

key_len="1024"

if [ -f "Users" ]; then
    echo "\n Reading Users"
else
    echo "\n create Users with list of users"
fi



if [ -d "keys" ]; then
    echo "\n keys folder exists "
else
    echo "\n create keys folder"
    mkdir keys
    echo "\n create keys"
fi


echo "\n Creating $key_len bit RSA keys"
python CreateKeys.py Users $key_len



# - SecType : CONF, AUIN, COAI 
# - Sender/Receiver : sender and recipient of this message.
# - plain_text_file : contains the input plain-text file (in ASCII format)
# - cipher_text_file : contains the output of the encryption algorithms (in binary format)
# - DigestAlg : sha512, sha3-512
# - EncryAlg : des-ede3-cbc, aes-256-cbc

OPT="CONF"
sender="user1"
receiver="user2"
digest_algo="sha3-512"
encryption_algo="des-ede3-cbc"
plain_text_file="plain.txt"
cipher_text_file="cipher"

python CreateMail.py $OPT $sender $receiver $plain_text_file $cipher_text_file $digest_algo $encryption_algo $key_len

plain_text_file="received_msg.txt"
cipher_text_file="cipher"

echo "\n\n Reading Mail"
python ReadMail.py $OPT $sender $receiver $cipher_text_file $plain_text_file $digest_algo $encryption_algo $key_len


diff plain.txt received_msg.txt
comp_value=$?
if [ $comp_value -eq 1 ]; then
    echo "\n\n Intrution Detected"
else
    echo "\n\n Sent and received message is identical"
fi


