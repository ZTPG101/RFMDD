FROM python:3.12-slim

WORKDIR /locust
COPY locustfile.py .

RUN pip install locust

CMD ["locust", "-f", "locustfile.py", "--host", "http://target_app:8000"]