import json

from tensorflow import keras

import predict
import readkratos

def run():
    model = keras.models.load_model('saved_kff_model.h5')

    file_name = 'test_kratos.log'

    filtered_data = readkratos.filter_kratos(file_name)
    processed_data = readkratos.process_data(filtered_data)
    split_data = readkratos.time_split(processed_data, seconds=300)
    dataset = readkratos.build_dataset(split_data)

    alert_data = predict.produce_alerts(model, dataset, split_data)
    predict.write_json_alerts(alert_data, 'logscan_alerts.json')


if __name__ == '__main__':
    run()
