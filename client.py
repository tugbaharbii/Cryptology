import socket #sunucuyla bağlantı kurmak için
import json
import threading #Mesajları dinlemek için arka planda bir işi parçacığı çalıştırmak için.
from cryptograpy_utils import RSAKeyManager, AESCipher



def receive_messages(client_socket, rsa_manager, aes_cipher, is_connected): #Bu fonksiyon, istemcinin sunucudan gelen mesajları almasını ve işlemesini sağlar.
    while is_connected[0]: #bağlantı devam ettiği sürece mesajları dinle.
        try:
            message = client_socket.recv(2048).decode() #sunucudan gelen veriyi al decode ile gelen bayt veriyi string'e dönüştür.
            if not message: #eğer mesaj boşsa ,sunucuyla bağalntı kesilmiştir.
                print("\nDisconnected from server")
                is_connected[0] = False
                break

            data = json.loads(message) #mesajı JSON formatından bir python sözlüüğüne çevir.
            print("\n" + "="*50)
            print("Received data from server:")
            print(json.dumps(data, indent=2))#gelen mesajı detaylı bir şekilde , okunabilir formatta ekrana yazdır.
            print("="*50 + "\n")

            if data["command"] == "error":
                print(f"Error from server: {data['message']}")
                continue

            if data["command"] == "aes_key": #sunucudan şifrelenmiş bir AES anahtarı aldığında işle.
                try:
                    aes_key_encrypted = data["aes_key"]# gelen şifrelenmiş AES anahtarını al.
                    print(f"Received encrypted AES key: {aes_key_encrypted}")
                    
                    decrypted_aes_key = rsa_manager.decrypt_with_private_key(aes_key_encrypted) #RSA özel anahtarıyla AES anahtarını çöz.
                    print(f"Decrypted AES key: {decrypted_aes_key}")
                    
                    aes_cipher.key = bytes.fromhex(decrypted_aes_key) #AES anahtarı bytes formatında aes_cipher nesnesine atanır.Bu anahtar daha sonra şifre çözme işlemleri için kullanılır.
                    print(f"AES key (bytes): {aes_cipher.key.hex()}")
                except Exception as e:
                    print(f"Error processing AES key: {e}")

            elif "encrypted_message" in data:
                try:
                    print(f"Received encrypted message: {data['encrypted_message']}")#eğer gelen veri encrypted_message anahtarını içeriyorsa , bu bir mesajdır.Şifrelenmiş mesaj ekrana yazdırılır.

                    decrypted_bytes = aes_cipher.decrypt(data["encrypted_message"]) #AES anahtarı kullanılarak mesaj çözülür.
                    plaintext = decrypted_bytes.decode()#şifrelenmiş baytları stringe dönüştürür.
                    print(f"Decrypted message: {plaintext}")

                    if "signature" in data and data["signature"]: #mesajın imzasını doğrulamak amaç.
                        signature = data["signature"]
                        print(f"Message signature: {signature}")
                        sender_public_key = data["sender_public_key"]
                        is_valid = rsa_manager.verify_signature(plaintext, signature, sender_public_key)#verify_signature : mesajın imzası,gönderennin açık anahtarıyla kontrol edilir.
                        print(f"Signature verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
                except Exception as e:
                    print(f"Error decrypting message: {e}")

        except Exception as e:
            print(f"Error receiving message: {e}")
            is_connected[0] = False
            break
def main():
    try:
        rsa_manager = RSAKeyManager() #RSAManager nesnesini oluşturur.Bu nesne RSA anahtarlarını yönetmek için kullanılır.
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#bir istemci oluşturulur
        client_socket.connect(("127.0.0.1", 12345))#IP adresine bağlanılır
        is_connected = [True] #soket bağlantısının durumunu izlemek için bir liste oluşturulur.

        client_name = input("Enter your name: ") #kullanıcıdan ismi alınır ve RSAManagerden bir RSA public key alınır.
        public_key = rsa_manager.get_public_key()
        
        print("\n" + "="*50) #kullanıcıya RSA public ve private keyleri gösterilir.
        print("Your RSA Keys:")
        print(f"Public Key:\n{public_key}")
        print(f"Private Key:\n{rsa_manager.get_private_key()}")
        print("="*50 + "\n")

        registration_data = {#kayıt verilerini içeren bir sözlük oluşturulur.Bu,istemcinin adını ve public keyini içerir.
            "command": "register",
            "client_name": client_name,
            "public_key": public_key
        }
        
        print("Sending registration data:")#kayıt verileri JSON formatına dönüştürülüp sunucuya gönderilir.
        print(json.dumps(registration_data, indent=2))
        client_socket.send(json.dumps(registration_data).encode())

        aes_cipher = AESCipher(b'\x00' * 16)#Geçisi bir AES şifreleme nesnesi oluşturulur ve kayıt işlemenin tamamlandığı bildirilir.
        print(f"Registered as {client_name}.")

        receive_thread = threading.Thread(#Mesajları dinlemek için bir iş parçacığı başaltılır.
            target=receive_messages, 
            args=(client_socket, rsa_manager, aes_cipher, is_connected), 
            daemon=True
        )
        receive_thread.start()

        current_recipient = None #Şu anda seçili alıcıyı izlemek için bir değişken tanımlanır. 
        while is_connected[0]:
            try:
                recipient = input("\nRecipient (or 'quit' to exit): ")#kullanıcıdan mesaj göndermek istediği alıcı sorulur.
                if recipient.lower() == 'quit':
                    break

                # Yeni alıcı seçildiğinde ,sunucudan alıcı için bir AES anahtarı talep edilir.
                if current_recipient != recipient:
                    current_recipient = recipient
                    request_data = {
                        "command": "request_aes",
                        "sender": client_name,
                        "recipient": recipient
                    }
                    
                    print("\nSending AES key request:")
                    print(json.dumps(request_data, indent=2))
                    client_socket.send(json.dumps(request_data).encode())

                    # AES anahtarının gelmesi için kısa bir bekleme
                    import time
                    time.sleep(0.5)

                message = input("Message: ")#Kullanıcıdan mesaj metni istenir.Mesaj boşşa işlem atlanır.
                if not message:
                    continue
                
                #Kullsnıcıdan mesajı imzalamak isteyip istemediği sorulur.
                sign_message = input("Sign message? (y/n): ").lower() == 'y'
                
                #Mesaj AES algoritması kullanılarak şifrelenir ve orjinal ile şifreli mesaj gösterilir.
                encrypted_message = aes_cipher.encrypt(message)
                print(f"\nOriginal message: {message}")
                print(f"Encrypted message: {encrypted_message}")

                #Kullanıcı mesajı imzalamayı seçmişse ,mesaj RSA ile imzalanır ve imza gösterilir.
                signature = rsa_manager.sign_message(message) if sign_message else None
                if signature:
                    print(f"Message signature: {signature}")

                send_data = { #Gönderilen mesajın bilgilerini içeren bir sözlük oluşturulur.
                    "command": "send_message",
                    "sender": client_name,
                    "recipient": recipient,
                    "encrypted_message": encrypted_message,
                    "signature": signature
                }
                
                #mesaj bilgileri JSON formatına dönüştürülüp sunucuya gönderilir.
                print("\nSending message data:")
                print(json.dumps(send_data, indent=2))
                client_socket.send(json.dumps(send_data).encode())


            except Exception as e: #mesaj gönderiminde hata oluşursa bu hata yazdırılır ve bağlantı kesilmişse döngü sonlanır.
                print(f"Error sending message: {e}")
                if not is_connected[0]:
                    break

    except KeyboardInterrupt: #Kullanıcı klavyeden Ctrl+c ile programı durdurduğunda ,çıkış mesajı gösterilir.
        print("\nExiting...")
        
    except Exception as e: #Genel bir hata oluşursa hata mesajı yazdırılır. 
        print(f"Error: {e}")
    finally: #program sonlandığında soket kapatılır ve bağlantı durumu False yapılır.
        is_connected[0] = False
        client_socket.close()

if __name__ == "__main__":
    main()

#Bu kod istemci tarafından RSA ve AES ile şifreli iletişim kurmayı sağlayan bir uygulamanın temle bileşenlerini içeriyor.    