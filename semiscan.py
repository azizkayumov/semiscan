import os
import sys
from embedding import train_word2vec_model, scanner_to_vectors
from preprocess import deduplicate, pcap_to_csv, csv_to_ports
from clustering import cluster_data
import warnings

# Ignore all warnings
warnings.filterwarnings("ignore")

# get argument from command line
# python semiscan.py <dataset_path> <output_folder>
if len(sys.argv) != 3:
    print('Please provide the filename to preprocess')
    print('python preprocess.py <filepath.vectors> <ignore_if_exists>')
    sys.exit(1)

dataset_path = sys.argv[1]
dataset_name = os.path.basename(dataset_path).removesuffix('.pcap')
output_folder = sys.argv[2]
# check if dataset path exists
if not os.path.exists(dataset_path):
    print(f'Dataset path {dataset_path} does not exist')
    sys.exit(1)
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# preprocess dataset
csv_path = os.path.join(output_folder, f'{dataset_name}.csv')
pcap_to_csv(dataset_path, csv_path)
ports_path = os.path.join(output_folder, f'{dataset_name}.ports')
csv_to_ports(csv_path, ports_path)

# train word2vec model
train_word2vec_model(ports_path, "")

# convert scanner to vectors
keys_path = ports_path.replace('.ports', '.keys')
labels_folder = "labels"
vectors_path = os.path.join(output_folder, f'{dataset_name}.vectors')
scanner_to_vectors(ports_path, keys_path, labels_folder, vectors_path)

dedup_path = vectors_path.replace('.vectors', '.dedup')
deduplicate(vectors_path, dedup_path)

# perform clustering
cluster_data(dedup_path)
