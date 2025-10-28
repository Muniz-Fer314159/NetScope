import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading, queue, binascii, time

# ====== VISUAL ======
BG, PANEL, TEXT, ACCENT, DIM, ERROR = "#0b0f0a", "#071009", "#a7ff8d", "#39ff14", "#2a2f2a", "#ff6b6b"
FONT_MONO, FONT_TITLE, FONT_BUTTON = ("Consolas", 11), ("Consolas", 14, "bold"), ("Consolas", 11, "bold")

captured_packets, packet_queue = [], queue.Queue()
capturing = False

def now(): return time.strftime("%H:%M:%S")

def get_valid_interfaces():
    lst=[]
    for i in scapy.get_if_list():
        try:
            ip=scapy.get_if_addr(i)
            if ip not in ["0.0.0.0","127.0.0.1"]: lst.append(i)
        except: pass
    return lst

def packet_summary(pkt):
    proto="TCP" if pkt.haslayer(scapy.TCP) else "UDP" if pkt.haslayer(scapy.UDP) else "ICMP" if pkt.haslayer(scapy.ICMP) else "OTHER"
    if pkt.haslayer(scapy.IP):
        return f"{now()}  {len(captured_packets)-1}: {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst} [{proto}]"
    return f"{now()}  {len(captured_packets)-1}: (no IP) [{proto}]"

def sniff_thread(iface):
    global capturing
    def stop_filter(_): return not capturing
    try: scapy.sniff(iface=iface, store=False, prn=lambda p: packet_queue.put(p), stop_filter=stop_filter)
    except Exception as e: packet_queue.put(("__ERROR__",str(e)))

def start_sniff():
    global capturing
    capturing=True; set_led(True)
    iface=interface_var.get()
    threading.Thread(target=sniff_thread,args=(iface,),daemon=True).start()
    log(f"Capturando em: {iface}")

def stop_sniff():
    global capturing
    capturing=False; set_led(False)
    log("Captura interrompida.")

def log(msg):
    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END,f"[{now()}] {msg}\n")
    text_area.yview(tk.END)
    text_area.config(state=tk.DISABLED)

def process_packets():
    while True:
        try: pkt=packet_queue.get_nowait()
        except queue.Empty: break
        if isinstance(pkt,tuple) and pkt[0]=="__ERROR__":
            log(f"[ERRO] {pkt[1]}"); continue
        captured_packets.append(pkt)
        listbox.insert(tk.END,packet_summary(pkt))
    root.after(120,process_packets)

def show_packet(event=None):
    sel=listbox.curselection()
    if not sel: return
    idx=sel[0]; pkt=captured_packets[idx]; out=[]
    out.append(f"Índice: {idx}\nTimestamp: {now()}\n{pkt.summary()}\n")
    for layer in pkt.layers():
        out.append(f"Layer: {layer.name}\n{pkt[layer].show(dump=True)}\n{'-'*40}")
    try:
        raw=binascii.hexlify(bytes(pkt)).decode()
        out.append("== HEX DUMP =="); out.append(" ".join([raw[i:i+2] for i in range(0,len(raw),2)])[:6000])
    except: pass
    if pkt.haslayer(scapy.Raw):
        try:
            data=pkt[scapy.Raw].load.decode(errors="ignore")
            out.append("== PAYLOAD ==")
            out.append(''.join(ch if 32<=ord(ch)<=126 or ch in "\r\n\t" else '.' for ch in data)[:8000])
        except: out.append("== PAYLOAD BINÁRIO ==")
    win=tk.Toplevel(root); win.configure(bg=BG); win.title(f"Pacote {idx}")
    tk.Label(win,text=f"Pacote {idx}",fg=ACCENT,bg=BG,font=FONT_TITLE).pack()
    txt=scrolledtext.ScrolledText(win,width=120,height=40,bg=BG,fg=TEXT,font=FONT_MONO)
    txt.insert(tk.END,"\n".join(out)); txt.config(state=tk.DISABLED); txt.pack(padx=10,pady=10)

def save_selected():
    sel=listbox.curselection()
    if not sel: return
    idx=sel[0]
    scapy.wrpcap("selected_packet.pcap",[captured_packets[idx]])
    log(f"Pacote {idx} salvo.")

def export_payload():
    sel=listbox.curselection()
    if not sel: return
    idx=sel[0]; pkt=captured_packets[idx]
    if not pkt.haslayer(scapy.Raw): return
    data=pkt[scapy.Raw].load.decode(errors="ignore")
    printable=''.join(ch if 32<=ord(ch)<=126 or ch in "\r\n\t" else '.' for ch in data)
    open("payload.txt","w",encoding="utf-8").write(printable)
    log(f"Payload {idx} salvo em payload.txt")

def save_all():
    if captured_packets: scapy.wrpcap("all_packets.pcap",captured_packets); log("Todos salvos.")
    else: log("Nenhum pacote capturado.")

def clear(): text_area.config(state=tk.NORMAL); text_area.delete(1.0,tk.END); text_area.config(state=tk.DISABLED)

# ====== GUI ======
root=tk.Tk(); root.title("H4CKSNIFF v1.0"); root.geometry("1150x740"); root.config(bg=BG)
tk.Label(root,text="H4CKSNIFF - Terminal de Captura",font=FONT_TITLE,fg=ACCENT,bg=BG).pack(pady=(8,0))

text_area=scrolledtext.ScrolledText(root,width=140,height=6,font=FONT_MONO,bg=BG,fg=TEXT,insertbackground=TEXT,wrap=tk.WORD)
text_area.insert(tk.END,"[INFO] Use com autorização.\n"); text_area.config(state=tk.DISABLED); text_area.pack(padx=12,pady=(6,8))

iface_frame=tk.Frame(root,bg=BG); iface_frame.pack()
interfaces=get_valid_interfaces(); interface_var=tk.StringVar(value=interfaces[0] if interfaces else "")
menu=tk.OptionMenu(iface_frame,interface_var,*interfaces); menu.config(bg=PANEL,fg=TEXT,font=FONT_MONO,relief="flat",width=40); menu.pack(side=tk.LEFT,padx=(6,12))
led=tk.Label(iface_frame,text="●",font=("Consolas",16),fg="#444",bg=BG); led.pack(side=tk.LEFT)
set_led=lambda on: led.config(fg=ACCENT if on else "#444")

frame=tk.Frame(root,bg=BG); frame.pack(fill=tk.BOTH,expand=False,padx=12)
listbox=tk.Listbox(frame,width=110,height=14,font=FONT_MONO,bg=BG,fg=TEXT,selectbackground="#003300",bd=0,highlightthickness=0)
listbox.pack(side=tk.LEFT,padx=(0,10),pady=5); listbox.bind("<Double-Button-1>",show_packet)
scroll=tk.Scrollbar(frame,command=listbox.yview); scroll.pack(side=tk.LEFT,fill=tk.Y); listbox.config(yscrollcommand=scroll.set)

btnf=tk.Frame(frame,bg=BG); btnf.pack(side=tk.LEFT,fill=tk.Y,padx=10)
def btn(txt,cmd):
    b=tk.Button(btnf,text=txt,command=cmd,font=FONT_BUTTON,bg=DIM,fg=TEXT,relief="flat",width=28)
    b.bind("<Enter>",lambda e:b.config(bg=ACCENT,fg="#001100")); b.bind("<Leave>",lambda e:b.config(bg=DIM,fg=TEXT)); b.pack(pady=6)
btn("▶ Iniciar Captura",start_sniff); btn("■ Parar Captura",stop_sniff)
btn("👁 Ver Pacote",show_packet); btn("💾 Salvar Pacote",save_selected)
btn("✎ Exportar Payload",export_payload); btn("📦 Salvar Todos",save_all); btn("🧹 Limpar Log",clear)

status=tk.Label(root,text="Status: idle",font=FONT_MONO,fg=TEXT,bg=BG); status.pack(pady=(8,10))
def update_status(): status.config(text=f"Status: {'CAPTURANDO' if capturing else 'PARADO'} | Pacotes: {len(captured_packets)}"); root.after(500,update_status)
root.after(120,process_packets); root.after(500,update_status)
root.bind("<Escape>",lambda e: root.destroy())

root.mainloop()
