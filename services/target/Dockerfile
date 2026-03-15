FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    openssh-server \
    curl \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config \
    && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .

EXPOSE 8080 22

CMD service ssh start && python main.py