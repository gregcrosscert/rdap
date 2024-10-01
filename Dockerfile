# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt ./

# Install the required packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Expose the port that the RDAP server listens on
EXPOSE 3030 

# Define the command to run the application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:3030", "rdap_server:app"]

