import json
import argparse
from datetime import datetime, timedelta

def parse_custom_date(date_str):
    # Add additional date formats as needed
    custom_formats = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ"]
    for fmt in custom_formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            pass
    # If none of the custom formats match, try parsing with ISO 8601 format
    return datetime.fromisoformat(date_str.rstrip("Z"))

def shift_timestamp(json_data, reference_date_str, nested_key):
    # Parse the reference date string to a datetime object
    reference_date = parse_custom_date(reference_date_str)

    # Find the most recent date for the specified nested key and calculate the time shift
    valid_dates = [parse_custom_date(find_nested_value(data, nested_key)) for data in json_data if find_nested_value(data, nested_key)]
    most_recent_date = max(valid_dates) if valid_dates else reference_date
    time_shift = reference_date - most_recent_date

    # Shift the dates for the specified nested key based on the calculated time_shift
    for data in json_data:
        try:
            date_str = find_nested_value(data, nested_key)
            if date_str:
                date_datetime = parse_custom_date(date_str)
                shifted_datetime = date_datetime + time_shift

                # Update the '@timestamp' and event.created fields with the shifted timestamp value
                data['@timestamp'] = shifted_datetime.isoformat() + "Z"
                data['timestamp'] = shifted_datetime.isoformat() + "Z"
                data['event']['created'] = shifted_datetime.isoformat() + "Z"
                data['winlog']['event_data']['UtcTime'] = shifted_datetime.isoformat() + "Z"
        except KeyError:
            pass

    return json_data

def find_nested_value(data, nested_key):
    keys = nested_key.split('.')
    value = data
    for key in keys:
        if key in value:
            value = value[key]
        else:
            raise KeyError("Key not found: {}".format(nested_key))
    return value

def read_json_data_from_file(file_path):
    with open(file_path, "r") as file:
        json_data = json.load(file)
    return json_data

def write_jsonl_data_to_file(file_path, json_data):
    with open(file_path, "w") as file:
        for data in json_data:
            file.write(json.dumps(data) + "\n")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Shift the @timestamp field in JSON data and write as JSONL.")
    parser.add_argument("file_path", help="Path to the file containing JSON data (JSON array).")
    parser.add_argument("reference_date", nargs="?", default=None, help="Reference date in custom format (e.g., '2023-08-01T16:00:00Z').")
    parser.add_argument("nested_key", help="Nested key in the JSON objects containing the timestamp to be shifted (e.g., 'data.created_at').")
    args = parser.parse_args()

    # Read JSON data from the file
    json_data = read_json_data_from_file(args.file_path)

    # If the reference date is not provided as an argument, set it to the current time
    reference_date_str = args.reference_date if args.reference_date else datetime.utcnow().isoformat() + "Z"

    # Call the function to shift the '@timestamp' field relative to the reference date
    shifted_json_data = shift_timestamp(json_data, reference_date_str, args.nested_key)

    # Save the updated JSON data as JSONL back to the file (optional, depending on your use case)
    write_jsonl_data_to_file("/tmp/evtx/tmp.json", shifted_json_data)

if __name__ == "__main__":
    main()

