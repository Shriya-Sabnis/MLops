# Use official Python image
FROM python:3.11-slim

# Set work directory inside container
WORKDIR /app

# Copy dependency list
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code and artifacts into container
COPY app ./app
COPY artifacts ./artifacts

# Expose port (inside container)
EXPOSE 8000

# Default command: run FastAPI with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
