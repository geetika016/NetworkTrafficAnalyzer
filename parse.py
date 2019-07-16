from scapy.all import *
import pandas as pd
from joblib import Parallel, delayed
pd.set_option('display.max_columns', None)  # or 1000
pd.set_option('display.max_rows', None)  # or 1000
pd.set_option('display.max_colwidth', -1)
from multiprocessing import Pool
import psutil
import os
import glob
import math

def ip_proto(pkt):
    proto_field = pkt.get_field('proto')
    return proto_field.i2s[pkt.proto]

def parse(file_name):
    df = pd.DataFrame()
    ip_length = []
    payload_original_len = []
    layer_type_len = []
    layer_type = []
    src = []
    dst = []
    protocol = []
    sport = []
    dport = []
    timestamp = []
    ether_count = 0

    with PcapReader(file_name) as pcap_reader:
        for packet in pcap_reader:
            if "IP" in packet:
                try:
                # ip_length.append(packet['IP'].len)
                # payload_original_len.append(len(packet['IP'].payload.original))
                    this_layer_type_len = (len(packet[type(packet['IP'].payload)].payload))
                    this_layer_type = (type(packet['IP'].payload))
                    this_src = (packet['IP'].src)
                    this_dst = (packet['IP'].dst)
                    this_protocol = (ip_proto(packet['IP']))
                    this_sport = (packet['IP'].sport)
                    this_dport = (packet['IP'].dport)
                    this_timestamp = (packet.time)

                    layer_type_len.append(this_layer_type_len)
                    layer_type.append(this_layer_type)
                    src.append(this_src)
                    dst.append(this_dst)
                    protocol.append(this_protocol)
                    sport.append(this_sport)
                    dport.append(this_dport)
                    timestamp.append(this_timestamp)
                except:
                    print "Missed packet"
            else:
                ether_count = ether_count + 1

    # df['ip_length'] = ip_length
    # df['payload_original'] = payload_original_len
    df['layer_len'] = layer_type_len
    df['layer_type'] = layer_type
    df['src'] = src
    df['dst'] = dst
    df['protocol'] = protocol
    df['sport'] = sport
    df['dport'] = dport
    df['timestamp'] = timestamp
    df['connections'] = df['src'].map(str) + " - " + df['dst'].map(str)

    df.to_csv(file_name + ".csv")
    return 1

def clean_files():
    del_files = glob.glob("splitted*")
    for file in del_files:
        os.remove(file)

def pcap_analysis():
    cpu_count = psutil.cpu_count(logical=False)
    file_size = os.path.getsize('packets.pcap')/(1024*1024.0)
    chunk_size = math.ceil(file_size/cpu_count)
    tcpdump_command = "tcpdump -r packets.pcap -w splitted.pcap -C " + str(chunk_size)
    os.system(tcpdump_command)

    filenames = glob.glob('splitted.*')

    pool = Pool(processes=cpu_count)
    results = pool.map(parse, filenames)

    csv_files = glob.glob("splitted*.csv")

    frames = []
    for file in csv_files:
        df = pd.read_csv(file)
        frames.append(df)

    final = pd.concat(frames)
    final.to_csv("data.csv")
