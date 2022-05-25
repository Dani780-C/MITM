import socket
import logging
import time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10020
adresa = '198.10.0.2'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit la adresa %s si portul %d", adresa, port)
sock.listen(5)

while True:

    conexiune = None
    while conexiune == None:
        conexiune, address = sock.accept()
        logging.info("Handshake cu %s", address)

    chunks = []

    while True:
        try:

            data = conexiune.recv(1024)
            logging.info('Content primit...' + str(len(data)))

            try:
                if data.decode('utf-8') == "":
                    conexiune.send("FIN".encode())

                    fisier_bytes = b''.join(chunks)

                    g = open("poza_server.png", "wb")
                    g.write(fisier_bytes)
        
                    g.close()
                    conexiune.close()
                
                    break
                else:
                    chunks.append(data)
                    #conexiune.send("ACCEPTAT".encode())
            except:
                chunks.append(data)
                #conexiune.send("ACCEPTAT".encode())

        except KeyboardInterrupt:

            print("\nCtrl + C ............. Terminare")
            fisier_bytes = b''.join(chunks)
            g = open("poza_server.png", "wb")
            g.write(fisier_bytes)
            g.close()
            conexiune.close()
            sock.close();
            logging.info('Socket inchis')
            exit()
