import json
import numpy as np
import datetime as dt

from tensorflow import keras

def predict(model, dataset_entry):
    X = np.vstack(dataset_entry)
    Y = model(X)

    return Y


def produce_alerts(model, dataset, split_data):
    alert_data = []
    for i in range(len(dataset)):
        y = predict(model, [dataset[i]])
        if y >= 0.5:
            source_ip = split_data[i][0][2]
            start_time = dt.datetime.fromtimestamp(split_data[i][0][1]).astimezone()
            end_time = dt.datetime.fromtimestamp(split_data[i][-1][1]).astimezone()

            tz_string = str(start_time.tzinfo.tzname(start_time))

            start_time = start_time.strftime("%m-%d-%Y %-l:%M%p ") + tz_string
            end_time = end_time.strftime("%m-%d-%Y %-l:%M%p ") + tz_string
            
            num_attempts = len(split_data[i])
            percent_success = round(dataset[i][0], 3)
            
            alert_data.append([source_ip, start_time, end_time, num_attempts, percent_success])
        
    return np.vstack(alert_data)


def write_json_alerts(alert_data, file_name):
    IP = alert_data[:, 0].tolist()
    ST = alert_data[:, 1].tolist()
    ET = alert_data[:, 2].tolist()
    N = alert_data[:, 3].tolist()
    P = alert_data[:, 4].tolist()
    with open(file_name, 'w') as outfile:
        json.dump({'Alerts': [{'Source IP': ip, 'Start Time': st, 'End Time': et, 'Number of Login Attempts': n, 'Percentage of Login Attempts Successful': p} for ip, st, et, n, p in zip(IP, ST, ET, N, P)]}, outfile, indent=4)
