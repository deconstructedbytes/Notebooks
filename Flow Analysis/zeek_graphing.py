import ipywidgets as widgets
import os
import tempfile
from io import StringIO
import pandas as pd
import numpy as np
import glob
import re
from IPython.display import display, HTML, Markdown
from collections import Counter
import validators
import networkx as nx
import matplotlib.pyplot as plt


zeek_cols = {'capture_loss': ['ts', 'ts_delta', 'peer', 'gaps', 'acks', 'percent_lost'],
 'conn': ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h',
        'resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
        'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
        'tunnel_parents'],
 'dhcp': ['ts', 'uids', 'client_addr', 'server_addr', 'mac',
        'host_name', 'client_fqdn', 'domain', 'requested_addr', 'assigned_addr',
        'lease_time', 'client_message', 'server_message', 'msg_types',
        'duration'],
 'dns': ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h',
        'resp_p', 'proto', 'trans_id', 'rtt', 'query', 'qclass',
        'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC',
        'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected'],
 'files': ['ts', 'fuid', 'tx_hosts', 'rx_hosts', 'conn_uids', 'source',
        'depth', 'analyzers', 'mime_type', 'filename', 'duration', 'local_orig',
        'is_orig', 'seen_bytes', 'total_bytes', 'missing_bytes',
        'overflow_bytes', 'timedout', 'parent_fuid', 'md5', 'sha1', 'sha256',
        'extracted', 'extracted_cutoff', 'extracted_size'],
 'http': ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h',
        'resp_p', 'trans_depth', 'method', 'host', 'uri', 'referrer',
        'version', 'user_agent', 'origin', 'request_body_len',
        'response_body_len', 'status_code', 'status_msg', 'info_code',
        'info_msg', 'tags', 'username', 'password', 'proxied', 'orig_fuids',
        'orig_filenames', 'orig_mime_types', 'resp_fuids', 'resp_filenames',
        'resp_mime_types'],
 'notice': ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h',
        'resp_p', 'fuid', 'file_mime_type', 'file_desc', 'proto', 'note',
        'msg', 'sub', 'src', 'dst', 'p', 'n', 'peer_descr', 'actions',
        'email_dest', 'suppress_for', 'remote_location.country_code',
        'remote_location.region', 'remote_location.city',
        'remote_location.latitude', 'remote_location.longitude'],
 'ntp': ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h',
        'resp_p', 'version', 'mode', 'stratum', 'poll', 'precision',
        'root_delay', 'root_disp', 'ref_id', 'ref_time', 'org_time', 'rec_time',
        'xmt_time', 'num_exts'],
 'ssl': ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h',
        'resp_p', 'version', 'cipher', 'curve', 'server_name', 'resumed',
        'last_alert', 'next_protocol', 'established', 'cert_chain_fuids',
        'client_cert_chain_fuids', 'subject', 'issuer', 'client_subject',
        'client_issuer', 'validation_status'],
 'stats': ['ts', 'peer', 'mem', 'pkts_proc', 'bytes_recv',
        'pkts_dropped', 'pkts_link', 'pkt_lag', 'events_proc', 'events_queued',
        'active_tcp_conns', 'active_udp_conns', 'active_icmp_conns',
        'tcp_conns', 'udp_conns', 'icmp_conns', 'timers', 'active_timers',
        'files', 'active_files', 'dns_requests', 'active_dns_requests',
        'reassem_tcp_size', 'reassem_file_size', 'reassem_frag_size',
        'reassem_unknown_size'],
 'weird': ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h',
        'resp_p', 'name', 'addl', 'notice', 'peer', 'source'],
 'x509': ['ts', 'id', 'certificate.version', 'certificate.serial',
        'certificate.subject', 'certificate.issuer',
        'certificate.not_valid_before', 'certificate.not_valid_after',
        'certificate.key_alg', 'certificate.sig_alg', 'certificate.key_type',
        'certificate.key_length', 'certificate.exponent', 'certificate.curve',
        'san.dns', 'san.uri', 'san.email', 'san.ip', 'basic_constraints.ca',
        'basic_constraints.path_len']
        }

def unpack_sources(list_of_sources):
    source_string = ""
    for source in list_of_sources:
        source_string += f"{source} ,"
    return source_string[:-2]


def create_temp_file(file_content):
    fp = tempfile.TemporaryFile()
    fp.write(file_content)
    fp.seek(0)
    df = pd.read_csv(StringIO(fp.read().decode()))

    df.insert(0, "date", df["_time"].apply(lambda x: x.split("T")[0]))
    df.insert(1, "hour", df["_time"].apply(lambda x: x.split("T")[1].split(":")[0]))
    df.hour = df.hour.astype(int)
    df.insert(2, "time", pd.to_datetime(df["_time"]))
    df.drop(["sourcetype", "_time"], axis=1, inplace=True)
    df.orig_h = df.orig_h.apply(convert_conflict)
    df.resp_h = df.resp_h.apply(convert_conflict)
    return df

def find_host_ip(dataframe):
    ips = Counter(dataframe.orig_h.tolist() + dataframe.resp_h.tolist())
    seen_count = 0
    for k,v in ips.items():
        if v > seen_count:
            most_seen = k
            seen_count = v
        
    return most_seen

pd.set_option('max_colwidth', 400)
pd.options.display.max_rows = 999
pd.options.display.max_columns = 50
pd.set_option('display.max_rows', None)


def summarize_fw_dataframe(df):

    summarized = df.groupby(["orig_h", "resp_h", "resp_p"])["duration"].sum().reset_index(name="duration")
    summarized.duration = summarized.duration/60
    mb_in = []
    mb_out = []
    for row in summarized.itertuples():
        combo_df = df[(df["orig_h"] == row.orig_h) &\
                      (df["resp_h"] == row.resp_h) &\
                     (df["resp_p"] == row.resp_p)]

        MB_IN = combo_df["resp_ip_bytes"].sum()/1024/1024
        MB_OUT = combo_df["orig_ip_bytes"].sum()/1024/1024
        mb_in.append(MB_IN)
        mb_out.append(MB_OUT)

        

    summarized["mb_in"] = mb_in
    summarized["mb_out"] = mb_out

    summarized["first_seen"] = combo_df.ts.min()
    summarized["last_seen"] = combo_df.ts.max()
    return summarized


def aggregate_session_analysis(df, established_only=True):
    display(Markdown(f"## Outbound traffic from {find_host_ip(df)}"))
    
    for port in df.resp_p.unique():
        threshold = 10
        if established_only:
            dests = df[(df.orig_h == find_host_ip(df) ) & (df.duration > 0) & (df.resp_p == port)].groupby(
                "resp_h")["duration"].sum().sort_values(ascending=False).head(
                threshold).reset_index()["resp_h"].tolist()
        else:
            dests = df[(df.orig_h == find_host_ip(df) ) & (df.resp_p == port)].groupby(
            "resp_h")["duration"].sum().sort_values(ascending=False).head(
            threshold).reset_index()["resp_h"].tolist()
    
        display(Markdown(f"**Traffic to port: {port}**"))
        if not dests:
            display(Markdown(f"**No sessions indicative of successful connection on this port.**"))
        for ip in dests:
            num = len(df[(df.resp_h == ip ) & (df.resp_p == port )])
            src = df[(df.resp_h == ip ) & (df.resp_p == port )]["orig_h"].unique()
            dur = df[(df.resp_h == ip ) & (df.resp_p == port )]["duration"].sum()
            resp_ip_bytes = df[(df.resp_h == ip ) & (df.resp_p == port )]["resp_ip_bytes"].sum()
            orig_ip_bytes = df[(df.resp_h == ip ) & (df.resp_p == port )]["orig_ip_bytes"].sum()
            first_seen = df[(df.resp_h == ip ) & (df.resp_p == port )]["ts"].min()
            last_seen = df[(df.resp_h == ip ) & (df.resp_p == port )]["ts"].max()
            display(Markdown(f"""**Source IP:** {unpack_sources(src)} ---> **Destination:** {ip}  
        **First Seen:** {first_seen} **Last Seen:** {last_seen}  
        **Total duration** {round(dur/60, 2)} minutes **Data In:** {round(resp_ip_bytes/1024/1024, 2)}MB **Data Out:** {round(orig_ip_bytes/1024/1024, 2)}MB **number of sessions** --> {num}"""))

def zeek_graph(df):
    summed = summarize_fw_dataframe(df)
    
    G = nx.DiGraph()
    
    # Adding nodes
    for log in summed.itertuples():
        if log.duration <=2 :
            continue
        G.add_edge(log.orig_h, log.resp_h, port = log.resp_p,# weight = (log.mb_in + log.mb_out) * 2000,
                   label = f"established - {log.resp_p}" if log.duration > 3 else f"attempted - {log.resp_p}",
                   mb = log.mb_in + log.mb_out
                   )
        
    pos = nx.spring_layout(G, seed=7, scale=5) 
    
    color_map = []
    size_map = []
    degrees = dict(G.degree)
    for node in G:
        if node in summed.orig_h.unique():
            color_map.append('green')
            size_map.append((degrees[node]+10) * 50)
        else: 
            color_map.append('blue') 
            size_map.append((degrees[node]+10) * 20)
    
    
    plt.figure(3, figsize=(20, 20), dpi=90)        
    # nodes
    nx.draw_networkx_nodes(G, pos, node_size=size_map, node_color=color_map, node_shape="h")
    
    # define edge specs
    icmp = [(u, v) for (u, v, d) in G.edges(data=True) if d["port"] == 0]
    ssh = [(u, v) for (u, v, d) in G.edges(data=True) if d["port"] == 22]
    ssh_weight = [d["mb"] * 1 for (u, v, d) in G.edges(data=True) if d["port"] == 22]
    web = [(u, v) for (u, v, d) in G.edges(data=True) if d["port"] in [80,443]]
    web_weight = [d["mb"] * 1 for (u, v, d) in G.edges(data=True) if d["port"] in [80,443]]
    windows = [(u, v) for (u, v, d) in G.edges(data=True) if d["port"] in [139, 445, 3389]]
    windows_weight = [d["mb"] *1 for (u, v, d) in G.edges(data=True) if d["port"] in [139, 445, 3389]]
    
    # draw edges
    nx.draw_networkx_edges(G, pos, edgelist=ssh, width=1, edge_color="black")
    nx.draw_networkx_edges(G, pos, edgelist=web, width=1, edge_color="red")
    nx.draw_networkx_edges(G, pos, edgelist=windows, width=windows_weight, edge_color="blue")
    
    other_ports = list(set(list(G.edges())) - set(list(ssh + windows + web)))
    nx.draw_networkx_edges( G, pos, edgelist=other_ports, width=1, alpha=0.1, edge_color="gray", style="--")
    
    # node labels
    nx.draw_networkx_labels(G, pos,  font_size=10, font_family="sans-serif", font_weight=40, alpha=1) #labels=make_links(pos)
    
    # edge labels

    # edge weight labels
    edge_labels = nx.get_edge_attributes(G, "label")
    nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=10)
    
    ax = plt.gca()
    ax.margins(0.1)
    #ax.set_title("Mapping")
    plt.axis("off")
    #plt.tight_layout()
    display(HTML(f"<center><h3>Zeek flows from {find_host_ip(df)}</h3></center>"))
    plt.show()



"""
file = widgets.FileUpload(multiple=False)
output = widgets.Output()

display(file, output)

def on_button_clicked(file_obj):
    output.clear_output()
    with output:
        print(file_obj["owner"].value[0]["name"])
        #try:
        df = create_temp_file(file_obj["owner"].value[0]["content"])
        zeek_graph(df)
        aggregate_session_analysis(df, established_only=False)


        

file.observe(on_button_clicked)
"""


#display(HTML("<h1> Zeek Flow Analysis</h1>"))

