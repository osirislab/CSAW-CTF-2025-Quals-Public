FROM python:3.10-slim

# Install necessary packages
RUN apt-get update && \
    apt-get install -y socat && \
    useradd -ms /bin/sh ctf

# Set working directory
WORKDIR /chal

# Copy challenge binary and flag
COPY ./overflow_me ./flag.txt ./

# Set proper permissions for security
RUN chown -R root:ctf /chal && \
    chmod 750 /chal && \
    chmod 550 /chal/overflow_me && \
    chown root:ctf /chal/flag.txt && \
    chmod 440 /chal/flag.txt

# Expose TCP port for remote connection
EXPOSE 21006

# Drop privileges and launch the challenge via socat
USER ctf

CMD ["socat", "-T60", "TCP-LISTEN:21006,reuseaddr,fork", "EXEC:/chal/overflow_me"]
