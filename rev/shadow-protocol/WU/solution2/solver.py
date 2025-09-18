from pwn import *
import time
import socket
import threading

context.log_level = 'debug'

CHALLENGE = '../handout/shadow_protocol'
PORT = 47831
HOST = '127.0.0.1'

# Calculate FAKE_TIME = now + 5 years (rounded to minute)
FAKE_TIME = ((int(time.time()) + 5 * 365 * 24 * 60 * 60) // 60) * 60

# Shared variable to receive the star_key
star_key_holder = {'value': None}


def listener():
    """Simple TCP listener to receive star_key from challenge side-channel."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, _ = s.accept()
        with conn:
            data = conn.recv(64)
            if data:
                try:
                    leaked = int(data.strip())
                    log.success(f"[+] Received star_key: {hex(leaked)}")
                    star_key_holder['value'] = leaked
                except ValueError:
                    log.error("Failed to parse star_key")


def solve():
    # Step 1: Start the listener in a separate thread
    thread = threading.Thread(target=listener, daemon=True)
    thread.start()

    # Step 2: Launch the challenge binary with fake time injected
    env = {
        'FAKE_TIME': str(FAKE_TIME),
        'LD_PRELOAD': './custom_time.so'
    }
    p = process(CHALLENGE, env=env)

    # Step 4: Wait for the listener to finish receiving star_key
    timeout = 5
    for _ in range(timeout * 10):
        if star_key_holder['value'] is not None:
            break
        time.sleep(0.1)
    else:
        log.error("Timeout waiting for star_key.")
        return

    star_key = star_key_holder['value']

    # p = process('../remote/shadow_protocol')
    p = remote('localhost', 3000)
    p.recvuntil(b"Encrypted message:\n")
    encrypted_line = p.recvuntil(b'\n').decode()
    print('encrypted line:', encrypted_line)
    log.info(f"[+] Encrypted from remote: {encrypted_line.strip()}")
    ciphertext = bytes.fromhex(encrypted_line.strip())


    # Step 5: Decrypt using the XOR scheme from the binary
    flag = ''
    for i, byte in enumerate(ciphertext):
        key_byte = (star_key >> (8 * (i % 8))) & 0xFF
        flag += chr(byte ^ key_byte)

    log.success(f"[✓] Flag: {flag}")


if __name__ == '__main__':
    solve()
