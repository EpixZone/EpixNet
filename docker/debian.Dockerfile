FROM python:3.12-slim-bookworm

RUN apt-get update
RUN apt-get -y install git openssl pkg-config libffi-dev python3-pip python3-dev build-essential libtool

RUN useradd -u 1600 -m service-epixnet

USER service-epixnet:service-epixnet

WORKDIR /home/service-epixnet

COPY requirements.txt .

RUN python3 -m pip install -r requirements.txt

# the part below is updated with source updates

COPY . .

ENTRYPOINT python3 epixnet.py --ui_ip "*" --fileserver_port 10042 \
    --tor $TOR_ENABLED --tor_controller tor:$TOR_CONTROL_PORT \
    --tor_proxy tor:$TOR_SOCKS_PORT --tor_password $TOR_CONTROL_PASSWD

CMD main

EXPOSE 42222 10042
