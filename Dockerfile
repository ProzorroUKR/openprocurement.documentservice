FROM python:3.6-jessie

RUN mkdir /app
WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY . /app
RUN rm -f cgi.py cgi.pyc
RUN pip install -e .[test,docs]
CMD ["gunicorn", "-w", "8", "-k", "gevent", "--paste", "config/service.ini", "--graceful-timeout=60"]
