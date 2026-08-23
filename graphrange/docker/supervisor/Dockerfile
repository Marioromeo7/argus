FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y docker.io && rm -rf /var/lib/apt/lists/*
COPY supervisor.py .
RUN pip install docker neo4j requests python-dotenv flask
CMD ["python", "supervisor.py"]
