from scapy.sendrecv import sniff
import traceback
from flow.PacketInfo import PacketInfo
from flow.Flow import Flow
import joblib
import sklearn
import pandas as pd
import json
import os
import platform
import xgboost

def block_user(ip_address):
    system = platform.system()
    if system == "Linux":
        print(f"Blocking traffic from {ip_address} using iptables")
        os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
        os.system(f"iptables -A OUTPUT -s {ip_address} -j DROP")
        os.system(f"iptables -A FORWARD -s {ip_address} -j DROP")
    elif system == "Windows":
        print(f"Blocking traffic from {ip_address} using Windows firewall")
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip_address}\" dir=in interface=any action=block remoteip={ip_address}/32")
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip_address} Outbound\" dir=out interface=any action=block remoteip={ip_address}/32")
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip_address} Forward\" dir=forward interface=any action=block remoteip={ip_address}/32")
    elif system == "Darwin":
        print(f"Blocking traffic from {ip_address} using pfctl (macOS firewall)")
        os.system(f"sudo pfctl -t blocklist -T add {ip_address}")
        os.system("sudo pfctl -f /etc/pf.conf")
    else:
        print("Unsupported operating system")

def format_label_dict(labels):
    labels_new=dict()
    for i in labels.keys():
        labels_new[int(i)] = labels[i]
    return labels_new

with open('labels.json','r') as f:
    labels=format_label_dict(json.loads(f.read()))

del format_label_dict

with open('cols.txt','r') as f:
    cols=f.read().split('\n')

dt=joblib.load("models/dt.joblib")
rf=joblib.load("models/rf.joblib")
xgb=joblib.load("models/xgb.joblib")
gbc=joblib.load("models/gbc.joblib")
mlp=joblib.load("models/mlp.joblib")
#scaler=joblib.load("models/scaler.joblib")

def predict(features):
    df=pd.DataFrame([features[:39]],columns=cols)
    #df=scaler.transform(df)
    res=[
        dt.predict(df)[0],
        rf.predict(df)[0],
        xgb.predict(df)[0],
        gbc.predict(df)[0],
        mlp.predict(df)[0]
    ]
    res=max(res)
    print("Prediction:",res)
    if res!=0:
        src=features[39]
        print(" Attack Source:",src)
        block_user(src)

FlowTimeout=600
current_flows=dict()

def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()
        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                predict(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                predict(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow
            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow
        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                predict(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                predict(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
    except AttributeError:
        return
    except:
        traceback.print_exc()

def snif_and_detect():

    while True:
        print("Begin Sniffing".center(20, ' '))
        sniff(prn=newPacket)
        for f in current_flows.values():
            predict(f.terminated())

snif_and_detect()