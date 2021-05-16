FROM python:3.9.5-slim
COPY ./ /app/
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/detector.py"]