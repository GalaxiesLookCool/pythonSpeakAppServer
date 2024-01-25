# syntax=docker/dockerfile:1
FROM scratch
COPY actualpythonserver
RUN pip install -r requirements.txt
CMD ["python main.py"]
