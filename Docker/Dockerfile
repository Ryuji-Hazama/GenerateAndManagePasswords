FROM python:3.12-slim

WORKDIR /app

COPY ./Docker/config.mpl /app
COPY ./Docker/requirements.txt /app
COPY ./GenManPw.py /app
COPY ./Tools.py /app
COPY ./NameList.txt /app
COPY ./Symbols.txt /app
COPY ./VerbList.txt /app
COPY ./WordList.txt /app

RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y xclip
RUN mkdir workDir temp

CMD ["python3", "GenManPw.py"]
