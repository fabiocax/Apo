FROM ubuntu
ENV PYTHONUNBUFFERED=1
RUN mkdir /app
WORKDIR /app
ADD . /app/
RUN apt-get update && apt-get  install -y git nmap python3 python3-pip python3-scapy python3-nmap
RUN pip install --upgrade pip
RUN pip install -r requeriments-network.txt
RUN ["/bin/sh", "update_base.sh"]
EXPOSE 5000
CMD ["python3","app.py"]
