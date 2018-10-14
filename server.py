import socket
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from ca import generateCertAndKeys 
  
listen_addr = '127.0.0.1'
port = 443   
encrypt_str = "encrypted_message="
sessionCipherKey_str = "sessionCipherKey="

filename, publicKey, private, certificate = generateCertAndKeys()

pem = private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

privKey = RSA.importKey(pem) 

# next create a socket object 
s = socket.socket()          
print("Socket successfully created")              
  
# Next bind to the port 
s.bind(('', port))         
print("socket binded to %s" %(port))
  
# put the socket into listening mode 
s.listen(5)      
print("socket is listening")           
  
print('Waiting for client')
# Establish connection with client. 
c, addr = s.accept()      
print("Client connected to the server: {}:{}".format(addr[0], addr[1])) 

# an endless loop until we interrupt it or  
# an error occurs 
while True: 
    # Wait until data is received
    data = c.recv(1024)
    data = data.replace("\r\n", '') #remove new line character

    if(data == "Contact Initiated"):
        c.send(filename.encode())
        print("Sending client server certificate to authenticate")
    elif(sessionCipherKey_str in data):
        data = data.replace(sessionCipherKey_str, '')
        # The server will decrypt the 'session cipher key' with its private key
        sessionCipherKey = PKCS1_OAEP.new(privKey) 
        print("Session cipher key is here: " + str(sessionCipherKey))
        c.send("Acknowledgment Message".encode())
        print("Sending acknowledgment message for receiving the sessionCipherKey")
    #Receiving the encrypted message and decrypt it
    elif(encrypt_str in data): 
        data = data.replace(encrypt_str, '')
        print("Encrypted message received = " + str(data))
        decrypted = sessionCipherKey.decrypt(data)
        c.send("Server: it is OK on my side".encode())
        print("Decrypted message = " + decrypted)

    else:
        break

# Close the connection with the client 
print("Ending up the connection")
c.send("Server stopped".encode())
c.close()