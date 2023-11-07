FROM python:3.9-slim

WORKDIR /usr/src/app

COPY ./server /usr/src/app/server
COPY ./modules /usr/src/app/modules
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 65432

ENV NAME World
ENV PYTHONPATH "${PYTHONPATH}:/usr/src/app/modules"

CMD ["python", "-u", "server/server.py"]
