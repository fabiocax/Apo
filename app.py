from scan import analisys,http_banner
import gradio as gr
from urllib.parse import urlparse

hosts=analisys()


def relatorio_gradle(url,scanfull):
    hosts=analisys(scanfull)
    cvss,scans =hosts.relatorio(url) 
    if hosts.cvss_score(cvss) == "Critical":
        color="red"
    elif hosts.cvss_score(cvss) == "High":
        color="brown"
    elif hosts.cvss_score(cvss) == "Medium":
        color="yellow"
    else:
        color="green"
        
    html='<center><b><p style="color:'+color+'">'+hosts.cvss_score(cvss).upper()+' ('+str(cvss)+')</p></b></center>'  
        
    return html,scans


iface = gr.Interface(relatorio_gradle, ["text",gr.inputs.Checkbox(label="Scan Full?")], 
                     [
                        gr.outputs.HTML(label="CVSS"),
                        gr.outputs.JSON(label=""),
                     ]
        )
iface.launch(server_port=5000,inline=False,server_name="0.0.0.0",prevent_thread_lock=True,enable_queue=True)

while True:
    pass

