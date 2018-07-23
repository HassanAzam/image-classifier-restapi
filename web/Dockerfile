FROM python:3.5.2
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install  --upgrade pip
RUN pip install -r requirements.txt
COPY . .
CMD [ "python3", "app.py" ]