# Use the official Python image
FROM python:3.9-slim

# Install required dependencies
RUN apt-get update && apt-get install -y \
    iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy the contents of the current directory into the container
COPY . /app

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Specify the ports that the application will use
EXPOSE 8000
EXPOSE 3333

# Specify the command to run the script by default
ENTRYPOINT ["python"]

# Specify the default script
CMD ["start.py"]
