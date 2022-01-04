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
    
    def __init__(self):
        self.cvss=0
        pass


    def host_port(host,port):

        return ""

    def scan_ports(self,host) -> dict :
        saida=headers_f()
        nmap = nmap3.Nmap()
        #-p1-65000
        open_ports=nmap.nmap_version_detection(host)
        for host in open_ports:
            try:
                ports_=open_ports[host]['ports']
                for port in ports_:
                    saida.add(port['portid']+'/'+port['protocol'],port)
            except:
                pass

        return saida

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
    
    def execute_script_vulners(self,host,port)  :
        saida=headers_f()
        nmap = nmap3.Nmap()
        #,'scripts/vulscan/'
        scripts=['scripts/nmap-vulners/']
        for scr in scripts:
            script=nmap.nmap_version_detection(host, args='-p'+str(port)+' --script='+scr)
            for item in script:
                try:
                    for line in script[item]['ports']:
                        for scripts in line['scripts']:
                            s=scripts['data']
                            for lne in s :
                                try:
                                    for line in s[lne]['children']:
                                        saida.add(line['id'],line)
                                except:
                                    pass
                except:
                    pass
            
            return saida
        
    def pipeline(self,url):
        
        pass
        
    def relatorio(self,url):
        ret={}
        host=urlparse(url)
        response=self.scan_ports(host.hostname)
        ret={
            host.hostname:{"port_scan":response},
            'cvss':self.cvss
            }
        return ret




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
