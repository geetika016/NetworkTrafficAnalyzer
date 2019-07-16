import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
from flask import Flask, jsonify, url_for
from flask import render_template
from flask import request
from flask import redirect
import os
import pandas as pd
import plotly
import plotly.plotly as py
import plotly.graph_objs as go
from sklearn.cluster import KMeans
import json
from sklearn.decomposition import PCA
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import normalize
from sklearn.ensemble import IsolationForest
from parse import clean_files, pcap_analysis
import plotly.figure_factory as ff
import numpy as np
from scipy.cluster.hierarchy import linkage
import decimal

app = Flask(__name__)

def feature_generation():  
    df = pd.read_csv("data.csv")

    unique_connections = df['connections'].unique()

    cluster_dataframe = pd.DataFrame()
    cluster_dataframe['connections'] = unique_connections


    max_packet_size = []
    min_packet_size = []
    mean_packet_size = []
    variance_packet_size = []
    total_packets = []
    sport = []
    dport = []
    protocol = []
    mean_time_diff = []
    connection_time = []


    for connection in unique_connections:
        temp = df.loc[df.connections == connection].sort_values(by='timestamp', ascending=True)
        temp['timestamp1'] = temp['timestamp'].shift(-1)
        temp['interval'] = temp['timestamp1'] - temp['timestamp']
        max_packet_size.append(temp.layer_len.max())
        min_packet_size.append(temp.layer_len.min())
        mean_packet_size.append(temp.layer_len.mean())
        variance_packet_size.append(temp.layer_len.var())
        total_packets.append(temp.shape[0])
        sport.append(temp.sport.mode()[0])
        dport.append(temp.dport.mode()[0])
        protocol.append(temp.protocol.mode()[0])
        mean_time_diff.append(temp.interval.mean())
        connection_time.append(temp.iloc[(temp.shape[0])-1]['timestamp'] - temp.iloc[0]['timestamp'])

    cluster_dataframe['max_packet_size'] = max_packet_size
    cluster_dataframe['min_packet_size'] = min_packet_size
    cluster_dataframe['mean_packet_size'] = mean_packet_size
    cluster_dataframe['variance_packet_size'] = variance_packet_size
    cluster_dataframe['total_packets'] = total_packets
    cluster_dataframe['sport'] = sport
    cluster_dataframe['dport'] = dport
    cluster_dataframe['protocol'] = protocol
    cluster_dataframe['mean_time_diff'] = mean_time_diff
    cluster_dataframe['total_connection_time'] = connection_time

    cluster_dataframe = cluster_dataframe.fillna(0)
    cluster_dataframe['protocol'] = LabelEncoder().fit_transform(cluster_dataframe['protocol'])
    cluster_dataframe.to_csv("cluster.csv", index=False)



@app.route("/file", methods=['POST'])
def load_pcap():
    f = request.files['file']
    f.save("data/" + "packets.pcap")
    os.chdir("data")
    clean_files()
    pcap_analysis()
    clean_files()
    feature_generation()
    os.chdir("..")
    return redirect(url_for('processed_pcap'))

@app.route("/dashboard")
def processed_pcap():
    df = pd.read_csv('data/data.csv')
    connections_x_packets = df['connections'].value_counts().reset_index()['index'][:13].values
    connections_no_packets = df['connections'].value_counts().reset_index()['connections'][:13].values
    connections_x_data = df.groupby("connections")['layer_len'].sum().reset_index().sort_values(by=['layer_len'], ascending=False)[:13]['connections'].values
    connections_no_data = df.groupby("connections")['layer_len'].sum().reset_index().sort_values(by=['layer_len'], ascending=False)[:13]['layer_len'].values
    all_connections_x_packets = ', '.join(["'" + str(x) + "'" for x in connections_x_packets])
    all_connections_no_packets = ', '.join(["'" + str(x) + "'" for x in connections_no_packets])
    all_connections_x_data = ', '.join(["'" + str(x) + "'" for x in connections_x_data])
    all_connections_no_data = ', '.join(["'" + str(x) + "'" for x in connections_no_data])

    sports_x_packets = df['sport'].value_counts().reset_index()['index'][:6].values
    sports_no_packets = df['sport'].value_counts().reset_index()['sport'][:6].values
    all_sports_x_packets = ', '.join(["'" + str(x) + "'" for x in sports_x_packets])
    all_sports_no_packets = ', '.join(["'" + str(x) + "'" for x in sports_no_packets])
    
    dports_x_packets = df['dport'].value_counts().reset_index()['index'][:6].values
    dports_no_packets = df['dport'].value_counts().reset_index()['dport'][:6].values
    all_dports_x_packets = ', '.join(["'" + str(x) + "'" for x in dports_x_packets])
    all_dports_no_packets = ', '.join(["'" + str(x) + "'" for x in dports_no_packets])

    sports_x_data = df.groupby("sport")["layer_len"].sum().reset_index().sort_values(by=["layer_len"], ascending=False)[:6]['sport'].values
    sports_no_data = df.groupby("sport")["layer_len"].sum().reset_index().sort_values(by=["layer_len"], ascending=False)[:6]['layer_len'].values
    all_sports_x_data = ', '.join(["'" + str(x) + "'" for x in sports_x_data])
    all_sports_no_data = ', '.join(["'" + str(x) + "'" for x in sports_no_data])

    dports_x_data = df.groupby("dport")["layer_len"].sum().reset_index().sort_values(by=["layer_len"], ascending=False)[:6]['dport'].values
    dports_no_data = df.groupby("dport")["layer_len"].sum().reset_index().sort_values(by=["layer_len"], ascending=False)[:6]['layer_len'].values
    all_dports_x_data = ', '.join(["'" + str(x) + "'" for x in dports_x_data])
    all_dports_no_data = ', '.join(["'" + str(x) + "'" for x in dports_no_data])

    protocols = df['protocol'].value_counts().reset_index()
    protocols["combined"] = "['" + protocols['index'].map(str) + "', " + protocols['protocol'].map(str) + "]"
    all_protocols =  " ,".join(protocols["combined"])
    return render_template('index.html', connections_no_packets = all_connections_no_packets, connections_x_packets = all_connections_x_packets, connections_no_data = all_connections_no_data, connections_x_data = all_connections_x_data, sports_x_packets = all_sports_x_packets, sports_no_packets = all_sports_no_packets, dports_x_packets = all_dports_x_packets, dports_no_packets = all_dports_no_packets, sports_x_data = all_sports_x_data, sports_no_data = all_sports_no_data, dports_x_data = all_dports_x_data, dports_no_data = all_dports_no_data, protocols = all_protocols)

@app.route("/visualize")
def visualize():
    cluster_dataframe = pd.read_csv("data/cluster.csv")
    X = cluster_dataframe.drop(['connections'], axis=1)
    clusters = 4
    X = normalize(X)
    reduced_data = PCA(n_components=clusters).fit_transform(X)

    #Outlier Test
    model = IsolationForest(contamination=0.05)
    model.fit(reduced_data)
    outliers = model.predict(reduced_data)
    outlier_frame = pd.DataFrame()
    outlier_frame['connections'] = cluster_dataframe['connections']
    outlier_frame['X'] = reduced_data[:, 0]
    outlier_frame['Y'] = reduced_data[:, 1]
    outlier_frame['isOutlier'] = outliers
    normal_connection = outlier_frame.loc[outlier_frame.isOutlier == 1]
    anomalous_connection = outlier_frame.loc[outlier_frame.isOutlier == -1]

    data = [go.Scatter(
        x = normal_connection['X'],
        y = normal_connection['Y'],
        text = normal_connection['connections'],
        hoverinfo = 'text',
        name="Normal Connections",
        mode = 'markers',
        marker=dict(
            color = 'rgb(34,140,217)'
        )
    ), go.Scatter(
        x = anomalous_connection['X'],
        y = anomalous_connection['Y'],
        text = anomalous_connection['connections'],
        hoverinfo = 'text',
        name = "Anomalous Connections",
        mode = 'markers',
        marker=dict(
            color = 'rgb(235,82,82)'
        )
    ) 
    ]

    graphJSON = json.dumps(data, cls=plotly.utils.PlotlyJSONEncoder)
    return render_template('visualize.html', graphJSON=graphJSON)


@app.route("/anomalies")
def anomalies():
    cluster_dataframe = pd.read_csv("data/cluster.csv")
    X = cluster_dataframe.drop(['connections'], axis=1)
    clusters = 4
    X = normalize(X)
    reduced_data = PCA(n_components=clusters).fit_transform(X)

    #Outlier Test
    model = IsolationForest(contamination=0.05)
    model.fit(reduced_data)
    outliers = model.predict(reduced_data)
    outlier_frame = pd.DataFrame()
    outlier_frame['connections'] = cluster_dataframe['connections']
    outlier_frame['X'] = reduced_data[:, 0]
    outlier_frame['Y'] = reduced_data[:, 1]
    outlier_frame['isOutlier'] = outliers
    normal_connection = outlier_frame.loc[outlier_frame.isOutlier == 1]
    anomalous_connection = outlier_frame.loc[outlier_frame.isOutlier == -1]
    return render_template('anomalies.html', items=list(anomalous_connection['connections']))

@app.route("/query")
def query():
    connection = request.args['connection']
    cluster_frame = pd.read_csv("data/cluster.csv")
    whole_frame = pd.read_csv("data/data.csv")
    big_frame = whole_frame.loc[whole_frame.connections == connection]
    frame = cluster_frame.loc[cluster_frame.connections == connection]
    src_ip = connection.split("-")[0]
    dst_ip = connection.split("-")[1]
    max_packet_size = frame.max_packet_size.iloc[0]
    min_packet_size = frame.min_packet_size.iloc[0]
    mean_packet_size = round(decimal.Decimal(frame.mean_packet_size.iloc[0]),2)
    total_packets = frame.total_packets.iloc[0]
    mean_time_diff = round(decimal.Decimal(frame.mean_time_diff.iloc[0]),2)
    assoc_sports = ", ".join(map(str, list(big_frame.sport.unique())))
    assoc_dports = ", ".join(map(str, list(big_frame.dport.unique())))
    assoc_protocols = ", ".join(list(big_frame.protocol.unique())).upper()
    total_bytes = big_frame.layer_len.sum()
    return render_template('details.html', connection=connection, src_ip = src_ip, dst_ip = dst_ip, assoc_sports = assoc_sports, assoc_dports = assoc_dports, assoc_protocols = assoc_protocols, max_packet_size = max_packet_size, min_packet_size = min_packet_size, mean_packet_size = mean_packet_size, total_packets = total_packets, total_bytes = total_bytes, mean_time_diff = mean_time_diff)

@app.route("/hierarchical")
def hierarchical():
    df = pd.read_csv("data/cluster.csv")
    X = df.drop(['connections'], axis=1)
    fig = ff.create_dendrogram(X, orientation='bottom', labels=list(df['connections']), linkagefun=lambda x: linkage(X, 'ward', metric='euclidean'))
    print list(df['connections'])
    fig['layout'].update({'width':1200, 'height':650, 'title': 'Hierarchical Clustering', 'margin': {'b':250}})
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return render_template('hierarchical.html', graphJSON=graphJSON)

@app.route("/")
def init():
    return render_template('home.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded = True)
