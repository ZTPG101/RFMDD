
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_HOME=/app
WORKDIR $APP_HOME

RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p $APP_HOME/network_logs
RUN mkdir -p $APP_HOME/templates # Ensure templates dir exists if not copied explicitly

EXPOSE 8000

# For production, remove --reload
CMD ["uvicorn", "rfm_api:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
