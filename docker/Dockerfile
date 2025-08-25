FROM python:3.12-alpine

RUN apk --update --no-cache --no-progress add git gcc libffi-dev musl-dev make openssl g++ autoconf automake libtool

RUN adduser -u 1600 -D service-epixnet

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
