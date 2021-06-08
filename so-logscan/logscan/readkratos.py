import json
import numpy as np
import datetime as dt
import time
from itertools import groupby

def filter_kratos(file_name):
    with open(file_name, 'r') as f:
        log_lines = [json.loads(line) for line in f.readlines() if "self-service/login" in line]

    return list(filter(lambda x: x.get("audience") == "audit", log_lines))


def process_data(filtered_data):
    sparse_data = []

    now = dt.datetime.now().astimezone()
    offset_seconds = (-now.tzinfo.utcoffset(now)).total_seconds()

    for x in filtered_data:
        sparse_data.append([
            1 if "Identity authenticated successfully" in x["msg"] else 0,
            time.mktime(dt.datetime.strptime(x["time"], "%Y-%m-%dT%H:%M:%SZ").timetuple()) - offset_seconds,
            x["http_request"]["headers"]["x-forwarded-for"].split(',')[-1]
        ])

    sparse_data.sort(key=lambda x: x[2])
    processed_data = [list(ip_group) for _, ip_group in groupby(sparse_data, lambda x: x[2])]
    return processed_data


def time_split(processed_data, seconds):
    split_data = []
    for i in processed_data:
        new_data = []
        current_time = i[0][1]
        for x in i:
            if x[1] < (current_time + seconds):
                new_data.append(x)
                
            else:
                split_data.append(new_data)
                new_data = [x]
                current_time = x[1]

        split_data.append(new_data)

    return split_data


def build_dataset(split_data):
    dataset = []
    for i in split_data:
        j = np.asarray(i)[:, 0].astype(int)
        ratio = sum(j) / len(j)
        fails = len(j) - sum(j)
        dataset.append([ratio, fails])

    return dataset
