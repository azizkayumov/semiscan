#!/bin/bash -e
#SBATCH --account=sds193
#SBATCH --job-name="semiscan"
#SBATCH --output=".results/semiscan.%j.%N.out"
#SBATCH --partition=compute
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=128
#SBATCH --mem=0
#SBATCH --export=ALL
#SBATCH -t 01:00:00

gzip -d $1 > $2

python3.9 -m venv .env
source .env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -W ignore semiscan.py $2 $3