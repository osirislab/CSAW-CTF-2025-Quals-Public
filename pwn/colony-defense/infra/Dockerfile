FROM ubuntu@sha256:dbdff34bb41cecdb07c79af373b44bb4c9ccba2520f014221fb95845f14bc6c1 AS builder

FROM pwn.red/jail:latest

COPY --from=builder / /srv

COPY ./chal /srv/app/run
COPY ./flag.txt /srv/app/

RUN chmod 755 /srv/app/run

EXPOSE 21001

ENV JAIL_TIME=60 \
    JAIL_PORT=21001