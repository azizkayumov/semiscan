#!/bin/bash -e
#SBATCH --job-name="semiscan"
#SBATCH --partition=debug
#SBATCH --account=sds193
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --mem-per-cpu=1000
#SBATCH --time=00:10:00
#SBATCH --output=".results/semiscan-%A_%a.out"

gzip -d $1 > $2 || true

python3.9 -m venv .env
source .env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -W ignore semiscan.py $2 $3