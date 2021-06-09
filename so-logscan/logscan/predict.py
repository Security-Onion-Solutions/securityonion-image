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
            start_timestamp = dt.datetime.fromtimestamp(split_data[i][0][1]).astimezone()
            end_timestamp = dt.datetime.fromtimestamp(split_data[i][-1][1]).astimezone()

            tz_string = str(start_timestamp.tzinfo.tzname(start_timestamp))

            start_time = start_timestamp.strftime("%m-%d-%Y %-l:%M%p ") + tz_string
            end_time = end_timestamp.strftime("%m-%d-%Y %-l:%M%p ") + tz_string
            
            num_attempts = str(len(split_data[i]))
            num_failed = str(dataset[i][1])
            
            alert_data.append([start_timestamp, source_ip, start_time, end_time, num_attempts, num_failed])
        
    alert_data.sort()
    return alert_data


def write_json_alerts(alert_data, outfile_path):
    lines = [json.dumps({'Source IP': i[1], 'Start Time': i[2], 'End Time': i[3], 'Number of Login Attempts': i[4], 'Number of Failed Login Attempts': i[5]}) for i in alert_data]
    with open(outfile_path, 'w') as outfile:
        [outfile.write(line + '\n') for line in lines]
    
    print(f'\n{len(alert_data)} alerts saved to {outfile_path}')
