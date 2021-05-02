FROM python:3.9.1-slim-buster

WORKDIR /usr/src/app

COPY ./requirements.txt .

RUN apt-get update && apt install -y \
    gcc \
    libpq-dev \
    libgtk-3-dev
RUN pip install -r requirements.txt && \
    rm requirements.txt

COPY ./ .
