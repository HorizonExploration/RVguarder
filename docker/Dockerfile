FROM docker.m.daocloud.io/library/python:3.13-slim

WORKDIR /app
COPY . /app
RUN python -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple && \
    python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .

EXPOSE 8780
CMD ["python", "-m", "openclaw_guard.main", "launch", "--host", "0.0.0.0", "--port", "8780", "--no-browser"]

