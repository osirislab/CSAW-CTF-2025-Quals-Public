FROM ubuntu@sha256:dbdff34bb41cecdb07c79af373b44bb4c9ccba2520f014221fb95845f14bc6c1

RUN apt-get update && apt-get install -y socat libssl-dev

RUN useradd -ms /bin/sh portal
WORKDIR /home/portal

COPY ./chal ./
COPY ./flag.txt ./

RUN chown -R portal:portal /home/portal && \
     chmod 750 /home/portal && \
     chmod 550 /home/portal/chal && \
     chown portal:portal /home/portal/flag.txt && \
     chmod 440 /home/portal/flag.txt

EXPOSE 21000

USER portal

CMD ["socat", "-T60", "TCP-LISTEN:21000,reuseaddr,fork", "EXEC:/home/portal/chal"]
