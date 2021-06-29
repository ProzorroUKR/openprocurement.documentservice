FROM python:3.6-slim-jessie

RUN mkdir /app
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install -y --no-install-recommends git
RUN pip install --upgrade pip && pip install -r requirements.txt .
RUN rm -f cgi.py cgi.pyc
RUN pip install -e .
CMD ["gunicorn", "-w", "4", "-k", "gevent", "--paste", "config/service.ini", "--graceful-timeout=60"]
