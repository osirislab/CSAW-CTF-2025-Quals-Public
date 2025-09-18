FROM ubuntu@sha256:021ffcf72f04042ab2ca66e678bb614f99c8dc9d5d1c97c6dd8302863078adba AS builder

FROM pwn.red/jail:latest

COPY --from=builder / /srv

COPY ./chal /srv/app/run
COPY ./flag.txt /srv/app/

RUN chmod 755 /srv/app/run

EXPOSE 21003

ENV JAIL_TIME=60 \
    JAIL_PORT=21003