FROM ubuntu@sha256:dbdff34bb41cecdb07c79af373b44bb4c9ccba2520f014221fb95845f14bc6c1

RUN apt-get update && apt-get install -y socat

RUN useradd -ms /bin/sh power
WORKDIR /home/power

COPY ./chal ./
COPY ./flag.txt ./

RUN chown -R power:power /home/power && \
     chmod 750 /home/power && \
     chmod 550 /home/power/chal && \
     chown power:power /home/power/flag.txt && \
     chmod 440 /home/power/flag.txt

EXPOSE 21005

USER power

CMD ["socat", "-T60", "TCP-LISTEN:21005,reuseaddr,fork", "EXEC:/home/power/chal"]