import socket
import threading #birden fazla istemci oluşturmak için
import os #AES anahtarı gibi rastgale veriler oluşturmak için fonk kullanımı
import json #mesajları json formatında gönderip almak için
from cryptograpy_utils import RSAKeyManager, AESCipher #RSA ve AES işlemlerini burada yapmak için

#kayıtlı istemcileri tutar. Her istemci adı , açık anahtarını ve istemciyle haberleşmeyi sağlayan socket nesnesini içerir.
clients = {}  


def broadcast_message(sender, recipient, encrypted_message, signature=None):#bir istemciden diğerine mesaj iletmeyi sağlar.
    """
   Şifrelenmiş mesajı göndericiden alıcıya iletin.
    """
    # Hem gönderenin hem de alıcının kayıtlı olup olmadığını kontrol edin
    if sender not in clients:
        print(f"Sender {sender} is not registered.")
        return False
    
    if recipient not in clients:
        print(f"Recipient {recipient} is not registered.")
        # Gönderene alıcının bulunamadığını bildir
        try:
            error_message = {
                "command": "error",
                "message": f"Recipient {recipient} is not registered."
            }
            clients[sender]["socket"].send(json.dumps(error_message).encode())
        except Exception as e:
            print(f"Error sending error message to sender: {e}")
        return False

    try:
        recipient_socket = clients[recipient]["socket"]
        sender_public_key = clients[sender]["public_key"]

        message_data = { #alıcıya gönderilecek olan veriler
            "sender": sender,
            "command": "send_message",
            "encrypted_message": encrypted_message,
            "signature": signature,
            "sender_public_key": sender_public_key,
        }
        recipient_socket.send(json.dumps(message_data).encode())#json.dumps message_datayı JSON formatına dönüştürür.
        return True                                    #encode JSON formatındaki stringi baytlara dnüştürür. #bunu yapmasının nedeni socket üzerinden veri gönderirken string yerine bayt veri tipini kullanılmasıdır.
    except Exception as e:
        print(f"Error broadcasting message: {e}")
        return False


def handle_client(client_socket, address):#istemcinin bağlantısını ve isteklerini işler.
    try:
        rsa_manager = RSAKeyManager()#RSA işlmeleri için bir Rsakeymanager nesnesi oluşturur .Bu nesne şifreleme ve şifre çzöme işlemlerinde kullanılır.
        client_name = None #istemci adı burada tutulur.Vrsayılan olarak none olarak başlatılır. 

        while True:
            message = client_socket.recv(2048).decode() #istemciden 2048 byte uzunluğunda bir mesaj alır.decode alına veriyi byte tipinden stringe dönüştürür.
            if not message:
                break

            data = json.loads(message)#gelen mesaj JSON formatına dönüştürülür. Bu sayede mesajdaki veriler sözlük olarak işlenir.
            print("\n" + "="*50)
            print(f"Received data from {address}:")
            print(json.dumps(data, indent=2))
            print("="*50 + "\n")

            command = data["command"] #mesajdaki command anahtarı kontrol edilerek hangi işlemin yapılacağı belirlenir.

            if command == "register": #istemciyi kayıt eder.
                client_name = data["client_name"] #istemcini adını alır.
                public_key = data["public_key"]  #istemcinin public keyini alır
                
                if client_name in clients: #sistemde zaten kullanıcı kayıtlı iste hata mesajı fırlatır.
                    error_message = {
                        "command": "error",
                        "message": "This client name is already taken."
                    }
                    client_socket.send(json.dumps(error_message).encode())
                    continue
                
                clients[client_name] = {"public_key": public_key, "socket": client_socket} #clients sözlüğüne istemcinin adı, açık anahtarı ve soket nesnesini ekler.
                print(f"Registered client {client_name}")
                print(f"Client's public key:\n{public_key}")

            elif command == "request_aes":  #AES anahtarını oluşturur ve iki istemciye gönderir.
                sender = data["sender"] #gönderen 
                recipient = data["recipient"]#alıcı isimleri alır.
                
                if sender not in clients or recipient not in clients:#gönderici veya alıcı kayıtlı değilse hata verir.
                    error_message = {
                        "command": "error",
                        "message": f"{'Sender' if sender not in clients else 'Recipient'} not registered."
                    }
                    client_socket.send(json.dumps(error_message).encode())
                    continue

                aes_key = os.urandom(16) #Rastgele 16 bytlık AES anahtarı oluşturulur.
                aes_key_hex = aes_key.hex() #anahtar , okunabilir bir hexadecimal forma dönüştürülür.
                print(f"\nGenerated AES key: {aes_key_hex}")

                aes_key_encrypted_for_sender = rsa_manager.encrypt_with_public_key( #AES anahtarı , gönderenin ve alıcının açık anahtarı ile şifrelenir.
                    clients[sender]["public_key"], aes_key_hex
                )
                aes_key_encrypted_for_recipient = rsa_manager.encrypt_with_public_key(
                    clients[recipient]["public_key"], aes_key_hex
                )

                print(f"Encrypted AES key for sender: {aes_key_encrypted_for_sender}")
                print(f"Encrypted AES key for recipient: {aes_key_encrypted_for_recipient}")

                sender_data = {
                    "command": "aes_key",
                    "aes_key": aes_key_encrypted_for_sender,
                    "recipient": recipient
                }
                
                recipient_data = {
                    "command": "aes_key",
                    "aes_key": aes_key_encrypted_for_recipient,
                    "sender": sender
                }

                clients[sender]["socket"].send(json.dumps(sender_data).encode()) #AES anahtarı, gönderen ve alıcıya şifreli bir şekilde gönderilir.
                clients[recipient]["socket"].send(json.dumps(recipient_data).encode())

            elif command == "send_message": #Şifrelenmiş mesajı bir istemciden diğerine iletir.
                print("\nForwarding encrypted message:")
                print(f"From: {data['sender']}")
                print(f"To: {data['recipient']}")
                print(f"Encrypted content: {data['encrypted_message']}")
                if data.get("signature"):
                    print(f"With signature: {data['signature']}")

                broadcast_message(data["sender"], data["recipient"],  #mesajı alıcı istemciye iletmek için bu fonksiyonu çağırılır.
                               data["encrypted_message"], data.get("signature"))

    except Exception as e:
        print(f"Error handling client: {e}")
    finally: #istemci bağıntısı kesildiğinde eğer istemci kayıtlıysa clients sözlüğünden silinir.
        if client_name and client_name in clients:
            print(f"Client disconnected: {client_name}")
            del clients[client_name]
        else:
            print(f"Unregistered client disconnected: {address}")
        client_socket.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)
    print("Server is running and listening for connections...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"New connection from {address}")
        threading.Thread(target=handle_client, args=(client_socket, address)).start()


if __name__ == "__main__":
    main()