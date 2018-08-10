FROM python:2.7-alpine

ENV TERM linux

RUN apk update && apk add --no-cache git netcat-openbsd openssl-dev libffi-dev g++ linux-headers make bash
COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY vbot.py /vbot.py

COPY exploit1.py /exploit1.py
COPY exploit.sh /exploit.sh
COPY poc1.py /poc1.py

COPY check1.py /check1.py
COPY check2.py /check2.py
COPY check3.py /check3.py
