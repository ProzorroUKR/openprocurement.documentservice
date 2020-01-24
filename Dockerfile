FROM python:2.7-slim-jessie

RUN apt-get update && apt-get install -y libsodium-dev git libevent-dev libzmq-dev libffi-dev libssl-dev gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app
RUN pip install --upgrade pip && pip install -r requirements.txt .

ENV TZ=Europe/Kiev
ENV LANG="en_US.UTF-8"
ENV LC_ALL="en_US.UTF-8"
ENV LC_LANG="en_US.UTF-8"
ENV PYTHONIOENCODING="UTF-8"
ENV JOURNAL_PREFIX=''

EXPOSE 6543

CMD ["chaussette", "paste:/app/etc/service.ini", "--host=0.0.0.0", "--port=6543", "--backend=gevent"]