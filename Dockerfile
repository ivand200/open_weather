FROM python:3.8

COPY . /src

WORKDIR /src

RUN pip install -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]

# gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --reload
