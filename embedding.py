import os
import sys
import time
import numpy as np
from gensim.test.utils import datapath
from gensim import utils
from gensim.models import Word2Vec

class MyCorpus:
    def __init__(self, filepath):
        self.filepath = filepath

    """An iterator that yields sentences (lists of str)."""
    def __iter__(self):
        for line in open(self.filepath):
            # assume there's one document per line, tokens separated by whitespace
            # remove first column (ip_src_32)
            line = line.split(',')[1:]
            # remove newline character
            line[-1] = line[-1].strip()
            # remove empty strings
            line = list(filter(None, line))
            yield line


def train_word2vec_model(ports_path, trained_model_path=""):
    sentences = MyCorpus(ports_path)
    filesize = os.path.getsize(ports_path)
    print(f'\n   => training w2v model on {ports_path} ({filesize / (1024 * 1024):.2f} MB)')
    now = time.time()

    # Create the Word2Vec model (if it exists, load it)
    if os.path.exists(trained_model_path):
        print(f'      loading model from {trained_model_path}...')
        model = Word2Vec.load(trained_model_path)
        model.build_vocab(sentences, update=True)
    else:
        print('      creating a new w2v model...')
        model = Word2Vec(vector_size=24, window=5, min_count=1, workers=4)
        model.build_vocab(sentences)

    # Train the model
    print("      training the model...")
    model.train(sentences, total_examples=model.corpus_count, epochs=10)

    # Save the model
    model_path = ports_path.replace('.ports', '.model')
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save(model_path)

    modelsize = os.path.getsize(model_path)
    print(f'      model saved at {model_path} ({modelsize / (1024 * 1024):.2f} MB)')

    # Save the keys
    keys = model.wv.key_to_index
    keys = sorted(keys, key=lambda x: int(x))
    keys_path = ports_path.replace('.ports', '.keys')
    os.makedirs(os.path.dirname(keys_path), exist_ok=True)
    with open(keys_path, 'w') as f:
        for key in keys:
            vec = model.wv[key]
            vector = np.round(vec, 6)
            row = f'{key},' + ','.join([str(v) for v in vector])
            f.write(f'{row}\n')
    print(f'      keys saved at {keys_path} (took {time.time() - now:.2f} seconds)')

def scanner_to_vectors(ports_path, keys_path, labels_folder, output_path):
    port_to_vectors = load_keys(keys_path)
    scanner_labels = load_labels(labels_folder)
    print(f'      converting scanners to vectors: {ports_path}')
    now = time.time()

    outfile = open(output_path, 'w')
    with open(ports_path, 'r') as f:
        for line in f:
            line = line.strip().split(',')
            ip_src_32 = line[0]
            label = 'unknown'
            if ip_src_32 in scanner_labels:
                label = scanner_labels[ip_src_32]
            ports = line[1:]
            vector = np.zeros(24)  # Default vector for unknown ports
            for port in ports:
                vector += port_to_vectors.get(port, np.zeros(24))
            vector /= len(ports) if ports else 1  # Avoid division by zero
            vector = np.round(vector, 6)
            vectors_str = ','.join(map(str, vector))
            outfile.write(f'{ip_src_32},{label},{vectors_str}\n')

    print(f'      scanner vectors saved at {output_path} (took {time.time() - now:.2f} seconds)')
    outfile.close()

def load_keys(keys_path):
    keys = {}
    with open(keys_path, 'r') as f:
        for line in f:
            line = line.strip().split(',')
            key = line[0]
            vec = np.array([float(x) for x in line[1:]])
            keys[key] = np.round(vec, 6)
    return keys


def load_labels(labels_folder):
    labels = {}
    for filename in os.listdir(labels_folder):
        filepath = os.path.join(labels_folder, filename)
        label = filename.removesuffix('.txt')
        with open(filepath, 'r') as f:
            for line in f:
                ipsrc = line.strip()
                labels[ipsrc] = label
    print(f'      loaded {len(labels)} labeled scanners')
    return labels
