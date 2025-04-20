# Dockerfile
FROM python:3.12-slim
WORKDIR /app
# COPY rfm_job.py .
# bring your CSVs in at build‑time or mount a volume at run‑time
RUN mkdir -p ./network_logs
COPY ./network_logs/ /app/network_logs
COPY ./RFM_table_generator ./ 

RUN pip install --no-cache-dir pandas
# ENV NETWORK_LOG_DIR=/app/network_logs \
#     INTERVAL_SECONDS=1800 \
#     MONETARY_COLUMN=bytes_sent
CMD ["python", "rfm_batch_processor.py"]
