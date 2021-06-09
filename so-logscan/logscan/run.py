from pathlib import Path

import json
import click

from tensorflow import keras

import predict
import readkratos

@click.command()
@click.argument('log_path', required=True)
def main(log_path: str) -> None:
    data_dir = f'{Path(__file__).parent.absolute()}/data'

    model = keras.models.load_model(f'{data_dir}/saved_kff_model.h5')

    filtered_data = readkratos.filter_kratos(log_path)
    processed_data = readkratos.process_data(filtered_data)
    split_data = readkratos.time_split(processed_data, seconds=300)
    dataset = readkratos.build_dataset(split_data)

    alert_data = predict.produce_alerts(model, dataset, split_data)
    outfile_path = f'{data_dir}/logscan.alerts'
    predict.write_json_alerts(alert_data, outfile_path)


if __name__ == '__main__':
    main()
