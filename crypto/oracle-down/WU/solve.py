from pwn import remote
import time

# stress tested with many connections using JS artillery, gradual joining

with open("intercepted_transmission.txt", "r") as f:
    transmission = f.read()

b64transmission = bytes.fromhex(transmission) # ciph includes IV at front
mac = b64transmission[:32]
ciph = b64transmission[32:]


BLOCK_LEN = 16

num_blocks = len(ciph) / BLOCK_LEN
assert num_blocks == int(num_blocks)
num_blocks = int(num_blocks)

conn = remote('localhost', 21004)
# conn = remote('chals.ctf.csaw.io', 21004)

def call_oracle(k, t):
    # run it
    input = mac + k
    inputhex = input.hex()

    # get median time taken for decryption
    times_called = []
    for _ in range(5):
        r0 = conn.recvline() # clear
        r1 = conn.recvline() # clear
        start_ns = time.perf_counter_ns()
        
        conn.sendline(inputhex)
        c = conn.recvline()
        
        end_ns = time.perf_counter_ns()
        
        times_called.append(end_ns - start_ns)

    times_called.sort()
    median = times_called[len(times_called) // 2]
    t.append(median)

    return t

def paddingoracle(ciph_po, num_blocks_po, curr, interm):
    timing = []
    place = (num_blocks-1)*BLOCK_LEN - curr
    blocker = place - 1
    if blocker >= 0:
        tmpciph = ciph_po[:blocker] + b'0' + ciph_po[blocker+1:]
    else: 
        tmpciph = ciph_po
    prefix = tmpciph[:place]
    suffix = tmpciph[place+1:]

    for adding in range(1, curr):
        changeplacesuffix = curr - adding - 1
        suffix = suffix[:changeplacesuffix] + (curr ^ interm[len(interm) - adding]).to_bytes(1, byteorder='big') + suffix[changeplacesuffix+1:]


    flag_workedonce = 0

    for j in range(256): # every byte option
        # print(j)
        # put together the existing ciphertext, new byte, and deciphered ciphertext
        try_this = prefix + (j).to_bytes(1, byteorder='big') + suffix
        # double check length, sanity check
        assert len(try_this) == len(ciph_po)

        timing = call_oracle(try_this, timing)
        # print(timing)

    # print(timing)
    ind = timing.index(max(timing))
    print(f"for offset {curr} we get {curr^ind}", flush=True)
    interm[len(interm) - curr] = curr^ind
    print(interm, flush=True)
    return interm

def through_blocks(ciph_tb):
    full_intermediary = []
    assert len(ciph_tb) == len(ciph)
    for _ in range(num_blocks - 2, -1, -1):
        interm = [0]*(BLOCK_LEN)
        for i in range(1, BLOCK_LEN+1):
            tt = paddingoracle(ciph_tb, num_blocks, i, interm)
        full_intermediary.insert(0, tt)
        ciph_tb = (0).to_bytes(16, byteorder='little') + ciph_tb[:-BLOCK_LEN]

    return full_intermediary

intermediary = through_blocks(ciph)


def get_plaintext(intermediary):
    with open("intercepted_transmission.txt", "r") as f: # might need to move things around to get this
        transmission = f.read()

    b64transmission = bytes.fromhex(transmission) # ciph includes IV at front
    mac = b64transmission[:32]
    ciphertext = b64transmission[32:]
    
    assert len(ciphertext) >= BLOCK_LEN, "Ciphertext must include IV"
    iv = ciphertext[:BLOCK_LEN]
    cipher_blocks = [iv] + [ciphertext[i:i+BLOCK_LEN] for i in range(BLOCK_LEN, len(ciphertext), BLOCK_LEN)]

    plaintext = b''

    for i, intermediate in enumerate(intermediary):
        prev_cipher = cipher_blocks[i]
        assert len(prev_cipher) == BLOCK_LEN

        # XOR intermediate with previous ciphertext block
        plain_block = bytes([intermediate[j] ^ prev_cipher[j] for j in range(BLOCK_LEN)])
        plaintext += plain_block

    return plaintext

print(get_plaintext(intermediary), flush=True)

conn.close()