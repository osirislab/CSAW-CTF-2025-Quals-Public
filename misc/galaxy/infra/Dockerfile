FROM python:3.13-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf

COPY main.py /home/ctf/main.py
RUN chown ctf:ctf /home/ctf/main.py
RUN chmod 555 /home/ctf/main.py  

RUN chmod 555 /home/ctf

EXPOSE 21009

CMD ["socat", "-v", "TCP-LISTEN:21009,reuseaddr,fork", "EXEC:'python3 -S /home/ctf/main.py',su=ctf"]
