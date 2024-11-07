FROM python:3.9

ENV HOME /root
WORKDIR /root
RUN pip install pymongo
COPY . .
EXPOSE 8080

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait
RUN pip install bcrypt
RUN pip install Flask

CMD /wait && python -u server.py 