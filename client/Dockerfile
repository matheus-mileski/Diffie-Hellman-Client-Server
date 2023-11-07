FROM python:3.9-slim

WORKDIR /usr/src/app

COPY ./client /usr/src/app/client
COPY ./modules /usr/src/app/modules
COPY requirements.txt .

COPY ../requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV NAME World
ENV PYTHONPATH "${PYTHONPATH}:/usr/src/app/modules"

CMD ["python", "-u", "client/client.py"]
