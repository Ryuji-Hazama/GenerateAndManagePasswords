FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt
RUN mkdir workDir temp

CMD ["python3", "GenManPw.py"]