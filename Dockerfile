FROM python:3.11

WORKDIR /app

COPY . .

RUN pip install flask

CMD ["python", "cli.py", "--file", "logs/auth.log"]