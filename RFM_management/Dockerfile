
FROM python:3.12-slim

# ENV PYTHONDONTWRITEBYTECODE=1
# ENV PYTHONUNBUFFERED=1
# ENV APP_HOME=/app
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless && apt-get clean && rm -rf /var/lib/apt/lists/*

# COPY requirements.txt .
COPY ./RFM_management .

COPY ./RFM_table/rfm_scores.csv ./rfm_scores.csv
RUN pip install --no-cache-dir -r requirements.txt

# COPY ./Database/database_utils.py .

RUN mkdir -p $APP_HOME/network_logs
RUN mkdir -p $APP_HOME/templates # Ensure templates dir exists if not copied explicitly

EXPOSE 8000

# For production, remove --reload
# CMD ["uvicorn", "rfm_api:app", "--host", "0.0.0.0", "--port", "8000"]
CMD ["python", "rfm_api.py"]
