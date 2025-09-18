from encrypt import encrypt_cbc, decrypt_cbc

SECRET_KEY = b'\x83v\x12U\xb1\x16v?+N\x9f\x16@\x16*Z\xae\x0b\xb0 2\x00U\r\x0b\xc4\xe9k4qv]'

if __name__ == '__main__':
    """Handle individual client connections"""
    while True:
        # Send welcome message
        welcome_msg = "This is Starline's secure comm-link. Please transfer valid communication here (or 'quit' to exit):\n> "
        # Receive data from client
        print(welcome_msg)
        data = input(welcome_msg)
            
        if not data:
            break
                
        if data.lower() == 'quit':
            print("Shutting down. Goodbye!\n")
            break
            
        if data.lower() == 'help':
            help_msg = "Commands:\n  - Send your valid communication through here\n  - 'quit' to exit\n  - 'help' for this message\n> "
            print(help_msg)
            continue
            
        try:
            # Decrypt the plaintext
            decrypted = decrypt_cbc(data, SECRET_KEY)

            print("Attempting to transmit valid communication...No connection found.")
            
                
        except Exception as e:
            print("Invalid communication.")
            pass
    print("Connection closed. Goodbye!")
