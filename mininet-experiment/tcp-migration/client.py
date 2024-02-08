import socket
import time
from datetime import datetime


def start_client():
    sent_count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print('TCP Client send to server1...')
        s.bind(('0.0.0.0', 33333))
        s.connect(('10.0.0.1', 11111))
        try:
            s.send(f'sent={sent_count} Hello, server1 test'.encode('utf-8'))
            data = s.recv(1024) 
            while True:
                if data:
                    now = datetime.now().strftime("%H:%M:%S")
                    print(f"[{now}] {data.decode('utf-8')}")
                    s.send(f'sent={sent_count} Hello, server1 test'.encode('utf-8'))
                    sent_count += 1
                    time.sleep(2)

                else:
                    break
                    
                data = s.recv(1024)
                
        except KeyboardInterrupt or Exception:
            s.shutdown(socket.SHUT_RDWR)

if __name__ == '__main__':
    start_client()
