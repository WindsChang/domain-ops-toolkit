FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

ENV PYTHONUNBUFFERED=1 \
    OPS_TOOLS_DATA_DIR=/data \
    OPS_TOOLS_HOST=0.0.0.0

EXPOSE 5000

CMD ["python", "ops_tool_web.py"]
