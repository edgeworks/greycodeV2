FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt

RUN if [ -n "$PIP_PROXY" ]; then \
        pip config set global.proxy "$PIP_PROXY" ; \
    fi
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

COPY selector /app/selector

CMD ["python", "-m", "selector.selector"]