# Dockerfile for greycode-core
FROM python:3.12-slim

ARG PIP_PROXY

WORKDIR /app

COPY ./requirements.txt ./

RUN if [ -n "$PIP_PROXY" ]; then \
        pip config set global.proxy "$PIP_PROXY" ; \
    fi
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY ./greycode_core ./

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
