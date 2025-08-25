FROM python:3.12-alpine

RUN apk --update --no-cache --no-progress add git gcc libffi-dev musl-dev make openssl g++ autoconf automake libtool
RUN apk add tor

RUN echo "ControlPort 9051" >> /etc/tor/torrc
RUN echo "CookieAuthentication 1" >> /etc/tor/torrc

RUN adduser -u 1600 -D service-epixnet

USER service-epixnet:service-epixnet

WORKDIR /home/service-epixnet

COPY requirements.txt .

RUN python3 -m pip install -r requirements.txt

RUN echo "tor &" > start.sh
RUN echo "python3 epixnet.py --ui_ip '*' --fileserver_port 10042" >> start.sh
RUN chmod +x start.sh

# the part below is updated with source updates

COPY . .

ENTRYPOINT ./start.sh

CMD main

EXPOSE 42222 10042
