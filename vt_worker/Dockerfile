FROM python:3.11-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}
ENV NO_PROXY=${NO_PROXY}

ENV PIP_PROXY=${HTTP_PROXY}

WORKDIR /app

COPY requirements.txt .
RUN pip config set global.proxy ${PIP_PROXY}
RUN pip install --no-cache-dir -r requirements.txt

COPY vt_worker/ .

CMD ["python", "worker.py"]