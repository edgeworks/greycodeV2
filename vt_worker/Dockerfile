FROM python:3.12-slim

ARG PIP_PROXY

WORKDIR /app

COPY requirements.txt .
RUN if [ -n "$PIP_PROXY" ]; then \
        pip config set global.proxy "$PIP_PROXY" ; \
    fi
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy worker code
COPY vt_worker/ /app/vt_worker/

# Copy shared core package
COPY greycode_core/ /app/greycode_core/

# Ensure /app is on sys.path
ENV PYTHONPATH=/app

# Run as module so package imports behave consistently
CMD ["python", "-m", "vt_worker.worker"]