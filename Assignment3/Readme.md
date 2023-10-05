1. KDC Server
    
    Use the following comand to start KDC server
``` shell
python kdc.py -p 1234 -o log.txt  -f pwdfile.txt
```

2. Sender Client
    
    Use the following comand to run client as sender 
``` shell
python client.py -n bob -m S -o alic -i assignment3.pdf -a 127.0.1.1 -p 1234
```

2. Receiver Client
    
    Use the following comand to run client as receiver 
``` shell
python client.py -n alic -m R -s test/outenc -d test/outfile -a 127.0.1.1 -p 1234
```

4. Sample sessions
-   KDC Server
```shell
$ python kdc.py -p 1234 -o log.txt  -f pwdfile.txt
[2021-04-09 10:42 PM] - Starting server at 127.0.1.1:1234
[2021-04-09 10:42 PM] - Server is listening on 127.0.1.1:1234
[2021-04-09 10:42 PM] - New connection : 127.0.0.1:52196 connected.
[2021-04-09 10:42 PM] - New message from 127.0.0.1:52196 - 301|127.0.1.1|2902|0mp9N3l4Oobsg9B3|bob
[2021-04-09 10:42 PM] - New message from 127.0.0.1:52196 - 305|HKhj8GUt5TigQX7vCXgYqIV5AJR4AjksTktMtmOtzJs=|bob
[2021-04-09 10:42 PM] - Client Disconnected: 127.0.0.1:52196
```

-   Sender Client
```shell
$ python client.py -n bob -m S -o Ketan -i 1.pdf -a 127.0.1.1 -p 1234
Contacting to KDC...
Registered, :b'302|bob'
Sleeps for 15 seconds...
Requesting for session key...
session key received: b'P~\x18\x06Ie\xf5\xca\xa0\x92cX\xd4\x85*\x0e'
Disconnected from KDC...
Connecting Ketan @ 127.0.35.50:3946
Sending 1.pdf to Ketan
enc data size: 105024 Bytes
File sent, Disconnecting!
Disconnected!
```
-   Receiver Client
```shell
$ python client.py -n Ketan -m R -s test/outenc -d test/outfile -a 127.0.1.1 -p 1234
Contacting to KDC...
Registered, :b'302|Ketan'
Disconnected from KDC...
Stated listining @ 127.0.35.50:3946
('127.0.0.1', 38698) got connected!
Received session_key: b'P~\x18\x06Ie\xf5\xca\xa0\x92cX\xd4\x85*\x0e' from bob
Waiting for file...
Received Data: 105024 Bytes 
Encrypted data written to test/outenc
Decrypted data written to test/outfile
[x] Done! Closing Server..

```

5. Known Issue
    - Receiver client should start its server before the sender start sending or sender's attempt to connect to receiver fails and it terminates.