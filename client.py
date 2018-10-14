import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA

from ca import validateCert 
  
# Define the secure port on which you want to connect 
port = 443          
host = '127.0.0.1'

# Create a socket object 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      

# connect to the server on local computer 
s.connect((host, port))

# Initiate contact with server
print('Initiating contact with server')
s.send("Contact Initiated".encode())

#Receive cert from server
serverCertificate = s.recv(1024).decode()
print('Received {} from server.'.format(serverCertificate))

# Send cert file to CA for validation
key = validateCert(serverCertificate)
print('Key gained from CA: {}'.format(str(key)))

if(key != "Goodbye"):
    #Encrypt key to session cipher key USING public key
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pubKey = RSA.importKey(pem)
    sessionCipherKey = PKCS1_OAEP.new(pubKey)

    print('Sending session cipher key: {}'.format(str(sessionCipherKey)))
    # Send encrypted session key
    s.send("sessionCipherKey=" + str(sessionCipherKey))
    # Should recieve acknowledgment if server is using session cipher key
    acknowledgment = s.recv(1024).decode()
    if(acknowledgment == "Acknowledgment Message"):
        print("Server is using the session cipher key")
        
    #Encrypt message and send to server
    message = b'This is my first python encryption code'
    h = SHA.new(message)
    encrypted = sessionCipherKey.encrypt(message)

    print('Sending encrypted message: {}'.format(str(encrypted)))

    s.send("encrypted_message=" + encrypted)

    #Server's reply to the client
    response = s.recv(1024).decode()
    if(response == "Server: it is OK on my side"):
        print("Server decrypted the message successfully")
    #Asking the server to end the connection
    s.send("Quit".encode())

else:
    # Will send 'Goodbye' because the certificate is not valid
    s.send(str(key).encode())

#Quit server response
print(s.recv(1024).decode()) 
s.close()