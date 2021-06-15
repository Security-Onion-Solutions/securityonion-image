from pathlib import Path
import configparser

import json

from tensorflow import keras

import predict
import readkratos

def main() -> None:
    config = configparser.ConfigParser()
    config.read('logscan.conf')
    for section in config.sections():
        for key in config[section]:
            print((key, config[section][key]))

    # model_path = config.get('logscan', 'model_path')
    # log_path = config.get('logscan', 'log_path')
    # out_path = config.get('logscan', 'out_path')

    model = keras.models.load_model(model_path)

    filtered_data = readkratos.filter_kratos(log_path)
    processed_data = readkratos.process_data(filtered_data)
    split_data = readkratos.time_split(processed_data, seconds=300)
    dataset = readkratos.build_dataset(split_data)

    alert_data = predict.produce_alerts(model, dataset, split_data)
    predict.write_json_alerts(alert_data, out_path)


if __name__ == '__main__':
    main()
