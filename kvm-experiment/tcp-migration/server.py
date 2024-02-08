import socket
from datetime import datetime
import time


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('10.0.0.1', 11111))
        s.listen(1)
        print('Server1 bind TCP on 11111...')
        client_sock, addr = s.accept()
        print(f'accepted {addr}')
        try:
            while True:
                data = client_sock.recv(1024)
                now = datetime.now().strftime("%H:%M:%S")
                if data:
                    print(f"[{now}] from {addr[0]}: {data.decode('utf-8')}")
                    client_sock.send(b'Hello, %s! This is server1' % addr[0].encode('utf-8'))
                    time.sleep(2)
                else:
                    break
                
        except KeyboardInterrupt or Exception:
            s.shutdown(socket.SHUT_RDWR)


if __name__ == '__main__':
    start_server()
