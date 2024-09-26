FROM python:3.11

RUN apt-get update && apt-get install -y libpcap-dev

COPY ./requirements.txt /

RUN pip install --no-cache-dir -r requirements.txt

COPY ./app /app

WORKDIR /app

CMD ["python", "./sonde_dns.py"]
