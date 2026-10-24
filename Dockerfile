FROM python:3.12-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN python -m playwright install --with-deps chromium

COPY app.py .
COPY Static ./Static

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

RUN chown -R 1000:1000 /app
USER 1000:1000

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
