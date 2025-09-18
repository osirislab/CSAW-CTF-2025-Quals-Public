FROM python:3.13-slim

RUN addgroup --system alexandria && adduser --system --ingroup alexandria alexandria

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY flag.txt /app/
COPY vault.txt /app/
COPY app.py /app/
COPY static/ /app/static/
COPY templates/ /app/templates/

RUN chown -R alexandria:alexandria /app

RUN find /app -type d -exec chmod 500 {} \;
RUN find /app -type f -exec chmod 400 {} \;

USER alexandria

CMD ["python", "app.py"]

