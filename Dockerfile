FROM python:3.12-bookworm

WORKDIR /app

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -m playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright

COPY app.py .
COPY Static ./Static

RUN chown -R 1000:1000 /app
USER 1000:1000

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]