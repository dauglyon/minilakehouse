FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 "pyjwt[crypto]==2.9.0" requests==2.32.3
COPY app.py ./
EXPOSE 9200
# Self-signed client-facing cert and the pinned Trino cert are created at startup (app.py).
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request,ssl; urllib.request.urlopen('https://localhost:9200/healthz', context=ssl._create_unverified_context())" || exit 1
CMD ["python", "app.py"]
