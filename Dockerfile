FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# (Optional but useful) allow writing ATT&CK cache file to /app/data
RUN mkdir -p /app/data

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Your new setup uses app.py + templates/index.html only
COPY app.py /app/app.py
COPY templates /app/templates

EXPOSE 8970

CMD ["gunicorn", "-b", "0.0.0.0:8970", "app:app", "--workers", "2", "--threads", "4", "--timeout", "120"]
