# Dockerfile (hub) — the single Village Trading Hub app
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python -I tools/gen_crypto.py     # bake notes.txt + BOTH config.bak.enc copies (WEB-3/4, JS-4 token)
ENV PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]              # dev server; use gunicorn for a real event
