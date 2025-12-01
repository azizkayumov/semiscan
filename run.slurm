#!/bin/bash -e
#SBATCH --account=sds193
#SBATCH --job-name="semiscan"
#SBATCH --constraint="lustre"
#SBATCH --output="joblogs/%A_%a.out"
#SBATCH --partition=compute
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=128
#SBATCH --mem=0
#SBATCH --export=ALL
#SBATCH -t 12:00:00
#SBATCH --mail-user=kayumovabduaziz@gmail.com
#SBATCH --mail-type=END,FAIL,TIME_LIMIT_80

SLURM_JOB_ID="$(squeue -u $LOGNAME |grep $HOSTNAME | awk '{print $1}')"
SCRATCH_DIR="/expanse/lustre/scratch/${USER}/temp_project"
mkdir -p "${SCRATCH_DIR}"

data_path="${SCRATCH_DIR}/$2"

python3.9 -m venv .env
source .env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -W ignore semiscan.py ${data_path} ${SCRATCH_DIR}