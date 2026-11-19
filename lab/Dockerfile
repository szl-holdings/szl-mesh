FROM python:3.15.2-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=7860

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY lab/requirements.txt /tmp/requirements.txt
COPY lab/constraints.txt /tmp/constraints.txt
RUN python -m pip install --no-cache-dir \
      --constraint /tmp/constraints.txt \
      --requirement /tmp/requirements.txt \
      --editable . \
    && useradd --create-home --uid 10001 mesh-lab
COPY --chown=mesh-lab:mesh-lab lab /app/lab
USER 10001
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/healthz', timeout=2).read()"
CMD ["uvicorn", "lab.app:app", "--host", "0.0.0.0", "--port", "7860", "--no-access-log"]
