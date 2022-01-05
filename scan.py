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
        self.cvss=[0]
        pass
    
    
    def host_port(self,url):
        port=0
        try:
            port=url.netloc.split(':')[1]
        except:
            if url.scheme =='http':
                port=80
            if url.scheme =='https':
                port=443
        return port


    def cvss_score(self,cvss):
        self.cvss.append(float(cvss))
        status=""
        if cvss < 4:
            status="Low"
        elif cvss >= 4 and cvss < 7:
            status="Medium"
        elif cvss >=  7 and cvss < 9:
            status="High"
        else :
            status="Critical"
        return status

    def scan_ports(self,host,port=None) -> dict :
        saida=headers_f()
        nmap = nmap3.Nmap()
        open_ports=nmap.nmap_version_detection(host)
        #-p1-65000
        for host in open_ports:
            try:
                ports_=open_ports[host]['ports']
                for port in ports_:
                    if port['state']=='open':
                        saida.add(port['portid'],port)
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
                                        saida.add(line['id'],self.cvss_score(float(line['cvss'])))
                                        
                                except:
                                    pass
                except:
                    pass
            
            return saida
        
    def pipeline(self,url):
        ret=headers_f()
        vulnerabilities=headers_f()
        host=urlparse(url)
        port=self.host_port(host)
        scan=self.scan_ports(host.hostname)
        scan_analisys=scan[str(port)]
        
        retorno={
            'portid':scan_analisys['portid'],
            'protocol':scan_analisys['protocol'],
            'service_name':scan_analisys['service']['name'],        
            'service_description':scan_analisys['service'],
            'vulnerabilities':{
                        'Critical':[],
                        'High':[],
                        'Medium':[],
                        'Low':[]},
            
            'cvss':0,
                }
        ### Scan vulners
        vulners=self.execute_script_vulners(host.hostname,port)
        retorno['vulnerabilities']['Critical']=list(filter(lambda score: vulners[score] == 'Critical', vulners))
        retorno['vulnerabilities']['High']=list(filter(lambda score: vulners[score] == 'High', vulners))
        retorno['vulnerabilities']['Medium']=list(filter(lambda score: vulners[score] == 'Medium', vulners))
        retorno['vulnerabilities']['Low']=list(filter(lambda score: vulners[score] == 'Low', vulners))
        retorno['cvss']=max(self.cvss)
        ret.add(host.hostname,retorno)
        
        return ret


    def relatorio(self,url):
        ret={}
        response=self.pipeline(url)
        ret=response
        return max(self.cvss),ret




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
