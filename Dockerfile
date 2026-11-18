# 出站探测演示：统一 Python 运行镜像
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY app /app/app

# 默认入口为探测 API；其他服务在 compose 中覆盖 command
EXPOSE 8000
CMD ["uvicorn", "app.probe.main:app", "--host", "0.0.0.0", "--port", "8000"]
