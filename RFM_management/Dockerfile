FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_HOME=/app
WORKDIR $APP_HOME

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless \
    # Add build-essential and libpq-dev if using psycopg2 (non-binary)
    # build-essential libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose the port the API runs on (defined in rfm_api.py/uvicorn command)
EXPOSE 8000     

# Default command to run the FastAPI application
# The batch job can be run using 'docker-compose run app python rfm_batch_processor.py'
CMD ["uvicorn", "rfm_api:app", "--host", "0.0.0.0", "--port", "8000"]
