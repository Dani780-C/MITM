import socket
import logging
import time
import sys
logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

chunks = []

port = 10020
adresa = '198.10.0.2'
server_address = (adresa, port)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
sock.connect(server_address)
logging.info('Handshake cu %s', str(server_address))

try:
    with open("poza_client.png", "rb") as file:
        
        bytes = file.read(1000)
        while bytes:
            chunks.append(bytes)
            bytes = file.read(1000)

    file.close()

    while True:
        
        try:
            
            for i in range(len(chunks)):

                bytes = chunks[i]
            
                sock.send(bytes)
                logging.info("Pachet ID-" + str(i) + " trimis...")
            
                # data = sock.recv(1024)
                
                logging.info('Raspuns primit de la server: ACCEPTAT') # + data.decode())

                time.sleep(1.5)
            
            sock.send("".encode())
            raise NameError("Terminat")

        except KeyboardInterrupt:
            print("\nCtrl + C ............. Terminare")
            logging.info('Socket inchis.')
            sock.close()
            exit()

        except NameError:
            # data = sock.recv(1024)

            logging.info("Raspuns primit de la server: FIN")#+ data.decode())

            exit()

except FileNotFoundError:
    print("Eroare... type: fisier inexistent")