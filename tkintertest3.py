import tkinter as tk
from scapy.all import rdpcap,TCP,UDP,ICMP

#reads packets from pcap file
packets=rdpcap("pcapfile0")


def on_option_select(value):
    if value != "Pick A Protocol":
        if value == "TCP":
            tcp_packets=[pkt for pkt in packets if TCP in pkt]
            label1.config(text="\n".join(str(pkt.summary()) for pkt in tcp_packets))
        if value =="UDP":
            udp_packets=[pkt for pkt in packets if UDP in pkt]
            label1.config(text="\n".join(str(pkt.summary()) for pkt in udp_packets))
        if value =="ICMP":
            icmp_packets=[pkt for pkt in packets if ICMP in pkt]
            label1.config(text="\n".join(str(pkt.summary()) for pkt in icmp_packets))
    if value == "Pick A Protocol":
        label1.config(text=f"")


window=tk.Tk()
window.title("Packet Filter")
window.geometry("1400x1000")

#Options
options=["Pick A Protocol","TCP","UDP","ICMP"]
#sets variable at positon 0 to selected option
selected_option=tk.StringVar()
selected_option.set(options[0])
#creates dropdown menu
dropdown=tk.OptionMenu(window,selected_option,*options,command=on_option_select)
dropdown.grid(row=0,column=0,padx=40,pady=40)
#label below
label1=tk.Label(window,text="",justify=tk.LEFT)
label1.grid(row=1,column=0,padx=40,pady=40)



window.mainloop()
