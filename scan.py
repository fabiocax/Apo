import nmap3
import socket 
from urllib.parse import urlparse
import socket
import requests


class headers_f(dict):
    def __init__(self):
        self = dict()

    def add(self, key, value):
        self[key] = value

        
class analisys:
    
    def __inti__(self):
        pass


    def port_scanner_(self,ip,port):
            s = socket.socket()
            try:
                s.connect((ip, port))
                s.settimeout(2)
                banner = s.recv(1024).decode().strip().replace('\n',' ').replace('\r',' ')
            except: 
                banner=""
            return banner

    def host_port(host,port):

        return ""

    def scan_ports(self,host) -> dict :
        saida=headers_f()
        nmap = nmap3.Nmap()
        #-p1-65000
        open_ports=nmap.nmap_version_detection(host)
        for lin in open_ports:
            try:
                for line in open_ports[lin]['ports']:
                    flag=port_scanner_(host,int(line['portid']))
                    if line['state'] == 'open':
                        lista_ports=flag
                        saida.add(line['portid']+"/"+line['protocol'], lista_ports)
            except:
                pass
        return saida

    def dns_brute_force(host):
        return nmap.nmap_dns_brute_script(host)

    def recursive_dns(self,host, recursive_dns=False, recursive_scan=False):
        saida = headers_f()
        saida.add(host,scan_ports(host))
        if recursive_dns == True:
            for hosts in dns_brute_force(host)  :
                if hosts['hostname'] != host:
                    if recursive_scan ==True:
                        saida.add(hosts['hostname'],[scan_ports(hosts['hostname'])])
                    else:
                        saida.add(hosts['hostname'],[{}])
        return saida

def http_banner(url):
    try:
        host,port=url.netloc.split(':')
    except:
        host=url.hostname
        if url.scheme == 'http':
            port=80
        else:
            port=443
    s = socket.socket()
    s.settimeout(2)
    s.connect((host, int(port)))
    head='HEAD / HTTP/1.1\nHost: 127.0.0.1\n\n'
    s.send(head.encode('utf-8'))
    return s.recv(1024).decode('utf-8').split('\r\n')
