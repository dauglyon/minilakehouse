FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 "pyjwt[crypto]==2.9.0" requests==2.32.3 \
    psycopg2-binary==2.9.9 boto3==1.35.49 "pyiceberg[pyarrow,sql-sqlite]==0.10.0"
COPY app.py index_table.py registry.json rgw_setup.py ./
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1
CMD ["python", "app.py"]
