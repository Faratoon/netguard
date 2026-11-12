FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping traceroute openssh-client curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
VOLUME ["/app/data"]
EXPOSE 8080

CMD ["uvicorn", "netguard.main:app", "--host", "0.0.0.0", "--port", "8080"]
