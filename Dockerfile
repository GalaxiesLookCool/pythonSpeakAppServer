# syntax=docker/dockerfile:1
# docker file of the python server to run
FROM python
COPY actualpythonserver .
RUN pip install -r requirements.txt
CMD ["ls"]
CMD ["python",  "main.py"]
