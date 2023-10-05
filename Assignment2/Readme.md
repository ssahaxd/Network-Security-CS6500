# CS6500 - Network Security

## Assignment 2 : Secure Email
Dr. Manikantan Srinivasan   
Even Sem. 2021

---

NAME :  **Sandip Saha**    
ROLL :  **CS20S044**

---

## 1. language and libraries  uses 
-  python 3
-  Crypto

## 2.   key generation
Create a new or modify the `Users` file which contain the name of the users. Create `keys` directory which will contain all the keys. Next generate the keys using the command `python CreateKeys.py <user_list> <RSA_key_size>`.

Example
    
``` sh
mkdir keys
python CreateKeys.py Users 2048
```

## 3.   encrypting email
After generating the RSA keys we can start encrypting emils using the `CreateMail.py`. First create a plain text file `plain.txt` and write the message you want to send. Now use this syntax to encrypt the content of plain.txt and store in the file `cipher`,

syntax: `python CreateMail.py SecType Sender Receiver plain_text_file cipher_text_file DigestAlg EncryAlg RSAKey-Size`

- SecType : CONF, AUIN, COAI 
- Sender/Receiver : sender and recipient of this message.
- plain_text_file : contains the input plain-text file (in ASCII format)
- cipher_text_file : contains the output of the encryption algorithms (in binary format)
- DigestAlg : sha512, sha3-512
- EncryAlg : des-ede3-cbc, aes-256-cbc

Example
    
``` sh
touch plain.txt
echo "IITM 2021" > plain.txt

# encrypt the email
python CreateMail.py COAI user1 user2 plain.txt cipher sha3-512 aes-256-cbc 2048
```

## 4.   decrypting email
decrypt email is similar to encrypt email. 

syntax: `python ReadMail.py SecType Sender Receiver cipher_text_file decrypted_text_file DigestAlg EncryAlg RSAKey-Size`

> Please note the position of the cipher_text_file and decrypted_text_file. 

Example

```sh
# Read the email
python ReadMail.py COAI user1 user2 cipher received_msg.txt sha3-512 aes-256-cbc 2048
```

This will create a file called `received_msg.txt` and store the decrypted plain text and print a line stating the Authentication is successful or not and.

Sample output:
```sh
IITM 2021   # plain text
```

## 4.   Testing 
The `script.sh` file is used to run various test cases. we have to modify the parameters and run.

``` sh
./script.sh 

 Reading Users

 keys folder exists 

 Creating 1024 bit RSA keys
 Processing: 100%

 Reading Mail


 Sent and received message is identical
```

you can modify the following lines in the `script.sh` to test for various cases.

```sh
key_len="1024"
...

OPT="CONF"
sender="user1"
receiver="user2"
digest_algo="sha3-512"
encryption_algo="des-ede3-cbc"
plain_text_file="plain.txt"
cipher_text_file="cipher"
...
```
