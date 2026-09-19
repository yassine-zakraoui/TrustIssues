# Train first (from the sentinel-bench checkout):
#   uv run --directory starter-kits/learned-monitor python -m monitor.train
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MONITOR_MODEL_PATH=/srv/model/monitor.joblib
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY monitor/__init__.py monitor/features.py monitor/model.py monitor/app.py ./monitor/
COPY model/monitor.joblib ./model/monitor.joblib

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin monitor
USER 10001:10001

EXPOSE 8080
CMD ["uvicorn", "monitor.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
