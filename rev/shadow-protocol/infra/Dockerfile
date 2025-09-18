# Dockerfile
FROM debian:12-slim

# Install runtime deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends socat openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Place the binary and run from its directory
WORKDIR /app
COPY remote/shadow_protocol /app/shadow_protocol
COPY entry.sh /app/entry.sh
RUN chmod +x /app/shadow_protocol /app/entry.sh

# Create the flag in the container at build time
RUN echo "csawctf{r3v3r51ng_5h4d0wy_pr070c0l5_15_c3r741n1y_n07_34sy}" > /app/flag.txt && \
    chmod 444 /app/flag.txt

# Run as non-root
RUN useradd -m ctf
USER ctf

EXPOSE 21002
CMD ["/bin/sh","-c", "exec socat -dd TCP-LISTEN:21002,reuseaddr,fork,nodelay EXEC:'/app/entry.sh',pipes"]
