FROM python:latest

EXPOSE 25
STOPSIGNAL SIGINT

RUN mkdir /app
COPY run.py /app
COPY requirements.txt /app
WORKDIR /app
RUN python -m pip install -r requirements.txt

ENTRYPOINT ["python", "run.py"]