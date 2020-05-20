# Base config
import configparser

parser = configparser.ConfigParser()
parser.read('SOCtopus.conf')

es_index = parser.get('es', 'es_index_pattern', fallback='so-*')

