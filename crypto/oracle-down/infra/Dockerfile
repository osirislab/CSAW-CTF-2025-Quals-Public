FROM ubuntu:22.04

RUN apt-get update && apt-get install -y socat

RUN apt-get install -y python3 
RUN apt-get install -y python3-dev
RUN apt-get install -y python3-pip
RUN pip3 install -U PyCryptodome

RUN useradd -m oracle
WORKDIR /home/oracle

COPY ./oracle.py ./ 
COPY ./encrypt.py ./

RUN chown oracle:oracle oracle.py && chmod 4755 oracle.py

EXPOSE 21004

CMD ["socat", "-T60", "TCP-LISTEN:21004,reuseaddr,fork","EXEC:python3 oracle.py,pty,echo=0"]