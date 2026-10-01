FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .

# Mount a Railway Volume here to persist SQLite and temporary-mail state.
RUN mkdir -p /app/data

EXPOSE 8080
CMD ["bash", "run.sh"]