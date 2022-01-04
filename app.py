from scan import analisys,http_banner
import gradio as gr
from urllib.parse import urlparse

hosts=analisys()


def relatorio_gradle(url):
    files =hosts.relatorio(url) 
    return 10,files


iface = gr.Interface(relatorio_gradle, "text", 
                     [
                        gr.outputs.Label(label="CVSS",num_top_classes=4),
                        gr.outputs.JSON(label=""),
                     ]
        )
iface.launch(server_port=5000,inline=False,server_name="0.0.0.0",prevent_thread_lock=True,enable_queue=True)

while True:
    pass

