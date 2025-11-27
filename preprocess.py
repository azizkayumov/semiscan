import os
import sys
import numpy as np

def deduplicate(vectors_path, output_path):
    seen = set()
    outfile = open(output_path, 'w')
    with open(vectors_path, 'r') as f:
        for line in f:
            line = line.strip().split(',')
            label = line[1]
            vector = ','.join(line[2:])
            if vector in seen:
                continue
            seen.add(vector)
            outfile.write(f'{label},{vector}\n')
    outfile.close()
    