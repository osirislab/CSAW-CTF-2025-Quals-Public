FROM python:3.11-slim

RUN useradd -r ctf

WORKDIR /app

COPY requirements.txt ./
RUN pip3 install -r requirements.txt

COPY ./ ./

RUN chown -R ctf /app

USER ctf

EXPOSE 4747

CMD ["gunicorn", "-b", "0.0.0.0:4747", "-w", "4", "app:app"]