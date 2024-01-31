FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./

RUN pip3 install --no-cache-dir -r /app/requirements.txt

COPY main.py .

CMD [ "python", "main.py" ]
