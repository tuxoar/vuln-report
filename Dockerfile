FROM python:3.13-slim

WORKDIR /app

# Add me a user

RUN groupadd --gid 1001 mrstreamlit && \
    useradd -m -u 1001 -g mrstreamlit -s /bin/bash mrstreamlit

# Install requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Set run as user
USER mrstreamlit

# Ports and Healthcheck
EXPOSE 8501
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Start her up
ENTRYPOINT ["streamlit","run","app.py","--server.port=8501","--server.address=0.0.0.0"]
