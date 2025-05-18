import nfstream
from nfstream import NFStreamer
import pandas as pd
import requests
import seaborn as sns
import numpy as np
import sklearn
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
import folium
from joblib import dump,load



token1 ="" # token for http://ipinfo.io
token2 = "" # token for https://api.abuseipdb.com
def summary(data):
    adress= pd.concat([data['src_ip'],data['dst_ip']]).unique()
    adress=adress.tolist()
    sum = data.groupby(['src_ip', 'dst_ip']).agg(
    total_bidirectional_bytes=pd.NamedAgg(column= 'bidirectional_bytes',aggfunc='sum'),
    total_src2dst_packets=pd.NamedAgg(column='src2dst_packets', aggfunc='sum'),
    total_dst2src_packets=pd.NamedAgg(column='dst2src_packets', aggfunc='sum'),
    total_src2dst_duration_ms=pd.NamedAgg(column= 'src2dst_duration_ms',aggfunc='sum'),
    src2dst_first_seen_ms=pd.NamedAgg(column= 'src2dst_first_seen_ms',aggfunc='min'),
    src2dst_last_seen_ms=pd.NamedAgg(column= 'src2dst_last_seen_ms',aggfunc='max'),
    dst2src_mean_ps=pd.NamedAgg(column= 'dst2src_mean_ps',aggfunc='mean')
    ).reset_index()
    
    addressTable= pd.DataFrame(columns=["ip","bogon","hostname","city","region","country","loc","org","postal","timezone"])
    addressTable2=pd.DataFrame()
    i=0
    for adresses in adress:
        geodane=sprawdz_geolokalizacje_ip(adresses)
        addressTable=addressTable._append(geodane,ignore_index=True)
    true_addressTable = addressTable[addressTable['bogon']!=True]
    addressTable = addressTable.sort_values(by='bogon')

    adress=true_addressTable['ip'].unique()
    adress=adress.tolist()
    for adresses in adress:
        
        repdane=sprawdz_reputacje_ip(adresses)
        repdanedf = pd.DataFrame([repdane])
        addressTable2=addressTable2._append(repdane,ignore_index=True)
    


    
    mltable = pd.DataFrame(columns=['id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'src_port',
       'dst_ip', 'dst_mac', 'dst_oui', 'dst_port', 'protocol', 'ip_version',
       'vlan_id', 'tunnel_id', 'bidirectional_first_seen_ms',
       'bidirectional_last_seen_ms', 'bidirectional_duration_ms',
       'bidirectional_packets', 'bidirectional_bytes', 'src2dst_first_seen_ms',
       'src2dst_last_seen_ms', 'src2dst_duration_ms', 'src2dst_packets',
       'src2dst_bytes', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
       'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
       'bidirectional_min_ps', 'bidirectional_mean_ps',
       'bidirectional_stddev_ps', 'bidirectional_max_ps', 'src2dst_min_ps',
       'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_max_ps',
       'dst2src_min_ps', 'dst2src_mean_ps', 'dst2src_stddev_ps',
       'dst2src_max_ps', 'bidirectional_min_piat_ms',
       'bidirectional_mean_piat_ms', 'bidirectional_stddev_piat_ms',
       'bidirectional_max_piat_ms', 'src2dst_min_piat_ms',
       'src2dst_mean_piat_ms', 'src2dst_stddev_piat_ms', 'src2dst_max_piat_ms',
       'dst2src_min_piat_ms', 'dst2src_mean_piat_ms', 'dst2src_stddev_piat_ms',
       'dst2src_max_piat_ms', 'bidirectional_syn_packets',
       'bidirectional_cwr_packets', 'bidirectional_ece_packets',
       'bidirectional_urg_packets', 'bidirectional_ack_packets',
       'bidirectional_psh_packets', 'bidirectional_rst_packets',
       'bidirectional_fin_packets', 'src2dst_syn_packets',
       'src2dst_cwr_packets', 'src2dst_ece_packets', 'src2dst_urg_packets',
       'src2dst_ack_packets', 'src2dst_psh_packets', 'src2dst_rst_packets',
       'src2dst_fin_packets', 'dst2src_syn_packets', 'dst2src_cwr_packets',
       'dst2src_ece_packets', 'dst2src_urg_packets', 'dst2src_ack_packets',
       'dst2src_psh_packets', 'dst2src_rst_packets', 'dst2src_fin_packets',
       'application_name', 'application_category_name',
       'application_is_guessed', 'application_confidence',
       'requested_server_name', 'client_fingerprint', 'server_fingerprint',
       'user_agent', 'content_type'])
    mltable2 = mltable._append(data)
    dataml = data.select_dtypes(include=[np.number])
    mltable = mltable._append(dataml)
    mltable = mltable.infer_objects()
    mltable = mltable.fillna(0)
    #mltable2 = mltable
    mltable2["mlscore"] = statyczna_analiza_ML(mltable)

    podejrzane=  mltable2[mltable2['mlscore']==1]
    

    address = addressTable.drop_duplicates(subset='ip')
    address = address[["ip","hostname","city","region","country","loc","org","postal","timezone"]]
    address = address.dropna(subset=["loc"])
    address = address.reset_index(drop=True)

    map = folium.Map(location=[52, 20],zoom_start=7)
    loc = address["loc"]
    loc.to_list()
    for localization in loc:
        localizationtable = str(localization).split(",")
        folium.Marker(
            location=localizationtable,  
            popup=f"ip: {address[address['loc']==localization]['ip'].values[0]} \n hostname: {address[address['loc']==localization]['hostname'].values[0]} \n city: {address[address['loc']==localization]['city'].values[0]} \n region: {address[address['loc']==localization]['region'].values[0]} \n country: {address[address['loc']==localization]['country'].values[0]} \n org: {address[address['loc']==localization]['org'].values[0]} \n postal: {address[address['loc']==localization]['postal'].values[0]} \n timezone: {address[address['loc']==localization]['timezone'].values[0]}",
            tooltip=f"ip: {address[address['loc']==localization]['ip'].values[0]}",    
        ).add_to(map)
    map.save("map2.html")
    
    return addressTable2,sum,podejrzane
    


def mapCountries(countryCode):
    
    url=f"https://restcountries.com/v3.1/alpha/{countryCode}"
    response=requests.get(url)
    data=response.json()
    lat = data[0]["latlng"]
    
    
    return lat



def wczytanieDanych(pcap):
    normal_streamer = NFStreamer(source=pcap, statistical_analysis = True)
    data = normal_streamer.to_pandas()
    
    for col in data.columns:
        if data[col].nunique() == 1 or data[col].isnull().any():
            data.drop(col, inplace=True, axis=1)

    return summary(data)


def wczytanieDanychML(pcapg,pcapb):
    good_streamer = NFStreamer(source=pcapg, statistical_analysis = True)
    good_flows = good_streamer.to_pandas()
    good_flows['label'] = 0
    print(1)
    bad_streamer = NFStreamer(source=pcapb, statistical_analysis = True)
    bad_flows = bad_streamer.to_pandas()
    bad_flows['label'] = 1
    if("normal_traffic.pcap" not in str(pcapg)): 
        good2_streamer = NFStreamer(source="normal_traffic.pcap", statistical_analysis = True)
        good2_flows = good2_streamer.to_pandas()
        good2_flows['label'] = 0
        print(2)
        good_flows = pd.concat(good_flows,good2_flows)
    if("not_normal_traffic.pcap" not in str(pcapb)):
        bad2_streamer = NFStreamer(source="not_normal_traffic.pcap", statistical_analysis = True)
        bad2_flows = bad2_streamer.to_pandas()
        bad2_flows['label'] = 1
        bad_flows= pd.concat(bad_flows,bad2_flows)
        print(3)
    

    data = pd.concat([good_flows, bad_flows], ignore_index=True)

    for col in data.columns:
        if data[col].nunique() == 1 or data[col].isnull().any():
            data.drop(col, inplace=True, axis=1)
    
    analiza_ML(data)
    
    return data

def statyczna_analiza_ML(data):

    model = load("decision_tree_model.joblib")
    predictions = model.predict(data)
    return predictions


def analiza_ML(data):
    data = data.select_dtypes(include=[np.number])

    mltable = pd.DataFrame(columns=['id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'src_port',
       'dst_ip', 'dst_mac', 'dst_oui', 'dst_port', 'protocol', 'ip_version',
       'vlan_id', 'tunnel_id', 'bidirectional_first_seen_ms',
       'bidirectional_last_seen_ms', 'bidirectional_duration_ms',
       'bidirectional_packets', 'bidirectional_bytes', 'src2dst_first_seen_ms',
       'src2dst_last_seen_ms', 'src2dst_duration_ms', 'src2dst_packets',
       'src2dst_bytes', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
       'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
       'bidirectional_min_ps', 'bidirectional_mean_ps',
       'bidirectional_stddev_ps', 'bidirectional_max_ps', 'src2dst_min_ps',
       'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_max_ps',
       'dst2src_min_ps', 'dst2src_mean_ps', 'dst2src_stddev_ps',
       'dst2src_max_ps', 'bidirectional_min_piat_ms',
       'bidirectional_mean_piat_ms', 'bidirectional_stddev_piat_ms',
       'bidirectional_max_piat_ms', 'src2dst_min_piat_ms',
       'src2dst_mean_piat_ms', 'src2dst_stddev_piat_ms', 'src2dst_max_piat_ms',
       'dst2src_min_piat_ms', 'dst2src_mean_piat_ms', 'dst2src_stddev_piat_ms',
       'dst2src_max_piat_ms', 'bidirectional_syn_packets',
       'bidirectional_cwr_packets', 'bidirectional_ece_packets',
       'bidirectional_urg_packets', 'bidirectional_ack_packets',
       'bidirectional_psh_packets', 'bidirectional_rst_packets',
       'bidirectional_fin_packets', 'src2dst_syn_packets',
       'src2dst_cwr_packets', 'src2dst_ece_packets', 'src2dst_urg_packets',
       'src2dst_ack_packets', 'src2dst_psh_packets', 'src2dst_rst_packets',
       'src2dst_fin_packets', 'dst2src_syn_packets', 'dst2src_cwr_packets',
       'dst2src_ece_packets', 'dst2src_urg_packets', 'dst2src_ack_packets',
       'dst2src_psh_packets', 'dst2src_rst_packets', 'dst2src_fin_packets',
       'application_name', 'application_category_name',
       'application_is_guessed', 'application_confidence',
       'requested_server_name', 'client_fingerprint', 'server_fingerprint',
       'user_agent', 'content_type', 'label'])
    

    mltable = mltable._append(data)
    mltable = mltable.fillna(0)
    data = mltable

    if 'label' in data.columns:
        # Obliczanie korelacji wszystkich cech z etykietą
        correlation_with_label = data.corr()['label'].sort_values(key=abs, ascending=False)

        # Usunięcie korelacji etykiety z samą sobą
        correlation_with_label = correlation_with_label.drop('label', errors='ignore')

        # Wybór 10 najbardziej skorelowanych cech
        top_10_correlated_features = correlation_with_label.head(10)

        print("10 cech najbardziej skorelowanych z etykietą:\n", top_10_correlated_features)
    else:
        print("Brak kolumny 'label' w danych.")
    
    X = data.drop('label', axis=1)
    y = data['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    default_model, default_accuracy, default_conf_matrix = train_and_evaluate_decision_tree(X_train, y_train, X_test, y_test)
    
    dump(default_model,"decision_tree_model.joblib")

    print("Dokładność modelu z domyślnymi parametrami:", default_accuracy)
    sns.heatmap(default_conf_matrix, annot=True, fmt="d")
    plt.title("Macierz błędów - Model domyślny")
    plt.show()
    

def train_and_evaluate_decision_tree(X_train, y_train, X_test, y_test, max_depth=None, criterion='gini'):
    
    tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
    tree_model.fit(X_train, y_train)

    
    predictions = tree_model.predict(X_test)

    
    accuracy = accuracy_score(y_test, predictions)
    conf_matrix = confusion_matrix(y_test, predictions)

    
    plt.figure(figsize=(20,10))
    plot_tree(tree_model, filled=True, feature_names=X_train.columns, class_names=['Normal', 'Malicious'], fontsize=10)
    plt.title("Wizualizacja drzewa decyzyjnego")
    plt.show()

    return tree_model, accuracy, conf_matrix


def sprawdz_geolokalizacje_ip(ip):
    token=token1
    url=f"http://ipinfo.io/{ip}/json?token={token}"
    response = requests.get(url)
    data=response.json()
    return data

def sprawdz_reputacje_ip(ip):
    token=token2
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {'Key': token}
    response = requests.get(url, headers=headers)
    data= response.json()['data']
    return  data



if __name__ == "__main__":
    wczytanieDanych("normal_traffic.pcap")
 