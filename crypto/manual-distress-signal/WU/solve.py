import requests
import ast
import base64

host = 'http://localhost:21022'
#host = 'http://chals.ctf.csaw.io:21022'
# host = 'https://manual-distress.ctf.csaw.io:443'

def bruteforce_decrypt(known, first=False):
    blocker = 'ççççççççççç'
    
    for i in range(33,127):
        trying = chr(i)
        payload = 'csawctf{' + known + trying + blocker
        control = 'csawctf{' + known + blocker + trying

        comp_payload = send_and_receive_payload(payload)
        comp_control = send_and_receive_payload(control)

        print(f"Trying: {known} + {trying}")
        print(len(comp_payload))
        print(len(comp_control))

        if len(comp_control) > len(comp_payload):
            print(f"Found: {known} + {trying}")
            return bruteforce_decrypt(known+trying)
    return known

def send_and_receive_payload(payload):
    # Send POST request to the /send endpoint
    response = requests.post(
        f"{host}/send",
        json={"data": payload}
    )
    # print(response)
    json_data = response.json()
    print(json_data)
    
    ciphertext_b64 = json_data.get("ciphertext", "")
    # get tls version from bytes 1-4 check tls 1.2 vulnerabilities  + crime from text on website
    if not ciphertext_b64:
        return b""

    ciphertext_bytes = base64.b64decode(ciphertext_b64)
    return ciphertext_bytes

if __name__ == "__main__":
    flag = bruteforce_decrypt('')

    print("Recovered value:", flag)
