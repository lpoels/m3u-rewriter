FROM python:3.11-slim

WORKDIR /app

RUN pip install requests

COPY gateway.py /app/gateway.py

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/gateway.py"]
