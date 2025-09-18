FROM python:3.9-slim-bullseye

RUN apt-get update && apt-get install -y \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libasound2 \
    libgtk-3-0 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install playwright

RUN useradd -r -m ctf

USER ctf

ENV PLAYWRIGHT_BROWSERS_PATH=/home/ctf/.cache/ms-playwright

RUN playwright install

WORKDIR /app

USER root
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . /app

RUN chown -R ctf /app

USER ctf

EXPOSE 4444

CMD ["gunicorn", "-b", "0.0.0.0:4444", "-w", "4", "admin:app"]
