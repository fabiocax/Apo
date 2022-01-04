from scan import analisys,http_banner
import gradio as gr
from urllib.parse import urlparse

hosts=analisys()

def relatorio(url):
    host=urlparse(url)
    res=hosts.scan_ports(host.hostname)
    files = {
        'relatrio':'---',
        host.hostname:{
            "port_scan":res},
        str(host.scheme+"://"+host.hostname):{
            "banner": http_banner(host),
        },
        'score':''
    }
    return 10,files


iface = gr.Interface(relatorio, "text", 
                     [
                        gr.outputs.Label(label="Score",num_top_classes=4),
                        gr.outputs.JSON(label=""),
                     ]
        )
iface.launch(server_port=5000,inline=False,server_name="0.0.0.0",prevent_thread_lock=True)

while True:
    pass

iface.close_all()