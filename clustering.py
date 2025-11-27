import os
import sys
import numpy as np
from fast_hdbscan import HDBSCAN


def cluster_data(datapath):
    X = np.genfromtxt(datapath, delimiter=",", dtype=str)
    partial_labels = X[:, 0]
    data_points = X[:, 1:].astype(float)

    class_map = { "unknown": -1 }
    class_id = 0
    for idx, label in enumerate(partial_labels):
        if label not in class_map:
            class_map[label] = class_id
            class_id += 1
        partial_labels[idx] = class_map[label]
    partial_labels = partial_labels.astype(int)
    partial_labeled_count = np.sum(partial_labels != -1)
    print(f'   => number of partially labeled samples: {partial_labeled_count} / {len(partial_labels)}')

    # clustering
    min_samples = 3
    min_cluster_size = 30
    clusterer = HDBSCAN(
        min_samples=min_samples,
        min_cluster_size=min_cluster_size,
        semi_supervised=True,
        ss_algorithm="bc",
    )
    clusterer.fit(data_points, y=partial_labels)
    cluster_labels = clusterer.labels_
    print("   => number of clusters: ", len(set(cluster_labels)))

    # Save results
    output_path = datapath.replace('.dedup', '.clusters')
    np.savetxt(output_path, cluster_labels, fmt="%d", delimiter=",")
    print(f"   => cluster labels saved to {output_path}")

    cluster_map = {}
    for (i, vector) in enumerate(data_points):
        vector = np.round(vector, 6)
        vector_str = ','.join(map(str, vector))
        cluster_map[vector_str] = cluster_labels[i]

    folder = os.path.dirname(datapath)
    vector_path = datapath.replace('.dedup', '.vectors')
    with open(vector_path, 'r') as f:
        for line in f:
            line = line.strip().split(',')
            ipsrc = line[0]
            label = line[1]
            vector = np.array([float(x) for x in line[2:]])
            vector = np.round(vector, 6)
            vector_str = ','.join(map(str, vector))
            cluster_id = cluster_map.get(vector_str, -1)
            cluster_file_path = os.path.join(folder, 'clusters', f'{cluster_id}.txt')
            os.makedirs(os.path.dirname(cluster_file_path), exist_ok=True)
            with open(cluster_file_path, 'a') as cf:
                cf.write(f'{ipsrc},{label}\n')
    print(f'   => cluster files saved to {os.path.join(folder, "clusters/")}')

