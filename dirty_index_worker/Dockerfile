FROM python:3.12-slim

ARG PIP_PROXY

WORKDIR /app

COPY requirements.txt .

RUN if [ -n "$PIP_PROXY" ]; then \
        pip config set global.proxy "$PIP_PROXY" ; \
    fi
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

ENV PYTHONPATH=/app

COPY greycode_core/ /app/greycode_core/
COPY dirty_index_worker/ /app/dirty_index_worker/

CMD ["python", "dirty_index_worker/worker.py"]