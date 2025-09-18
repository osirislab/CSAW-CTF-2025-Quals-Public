def text_to_ws(text):
    """
    Converts text to our Whitespace-like language:
    - ' ' -> space (increment)
    - '\t' -> tab (next cell)
    - '\n' -> newline (push/reset)
    - '\u00A0' -> nbsp (XOR with stack)
    """
    ws_program = []
    for char in text:
        # Convert character to ASCII value
        ascii_val = ord(char)
        # Add spaces equal to ASCII value
        ws_program.append(' ' * ascii_val)
        # Move to next cell
        ws_program.append('\t')
    # Add char for getting back
    # for char in text: 
    #     ws_program.append('\r')
    # Add 42
    ws_program.append(' ' * 42)
    # Add to stack
    ws_program.append('\n')
    ws_program.append('\u00A0')
    for char in text:
        # XOR
        ws_program.append('\r')
        ws_program.append('\u00A0')
    
    for i in range(2000000):
        # XOR
        for char in text:
            ws_program.append('\r')
            ws_program.append('\t')
        ws_program.append('\u00A0')
        for char in text:
            # go back
            ws_program.append('\r')
            ws_program.append('\u00A0')
    # Add final instruction to print all
    # ws_program.append('\n\u00A0')  # Push to stack and XOR
    return ''.join(ws_program)

def xor_first(text):
    fin = ""
    for i in text:
        fin = f"{fin}{chr(ord(i)^42)}"
    return fin

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python converter.py <input.txt> <output.ws>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        text = f.read()
    
    xored_text = xor_first(text)
    print(xored_text)

    ws_program = text_to_ws(xored_text)
    
    with open(sys.argv[2], 'w') as f:
        f.write(ws_program)
    
    print(f"Converted {len(text)} characters to {len(ws_program)} WS commands")