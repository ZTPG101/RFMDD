FROM python:3.9-slim

# Set environment variables to prevent Python from writing pyc files to disc
# and prevent Python from buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies if needed (e.g., for database drivers)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# Use --no-cache-dir to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container at /app
# This includes app.py and the templates/ directory
COPY . .

# Make port defined by FLASK_RUN_PORT available to the host
# Note: This EXPOSE is informational; the actual port mapping happens in docker-compose.yaml
# We use an ARG to get the port from the build context or default, then set an ENV
ARG FLASK_RUN_PORT=5000
ENV FLASK_RUN_PORT=${FLASK_RUN_PORT}
EXPOSE ${FLASK_RUN_PORT}

# Define the command to run the application
# Use gunicorn for production instead of flask run for better performance and stability
# CMD ["gunicorn", "--bind", "0.0.0.0:${FLASK_RUN_PORT}", "app:app"]
# --- OR ---
# For development/simplicity using the built-in server (as in your original code):
CMD ["python", "app.py"]