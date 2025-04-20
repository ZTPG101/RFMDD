FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /locust
COPY locustfile.py .

RUN pip install locust
# CMD locust -f locustfile.py \
#            --headless -u 50 -r 10 \
#            --host http://172.30.0.5:5000