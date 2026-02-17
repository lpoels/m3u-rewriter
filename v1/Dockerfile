FROM python:3.11-slim

WORKDIR /app

RUN pip install requests

COPY rewriter.py /app/rewriter.py

CMD ["python", "/app/rewriter.py"]
