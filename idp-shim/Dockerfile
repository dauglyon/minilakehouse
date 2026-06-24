FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 "pyjwt[crypto]==2.9.0" requests==2.32.3
COPY app.py .
EXPOSE 9000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/certs')" || exit 1
CMD ["python", "app.py"]
