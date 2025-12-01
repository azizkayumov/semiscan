#!/bin/bash -e
#SBATCH --job-name="semiscan"
#SBATCH --constraint="lustre"
#SBATCH --partition=debug
#SBATCH --account=sds193
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --mem-per-cpu=1000
#SBATCH --time=00:10:00
#SBATCH --output="joblogs/semiscan-%A_%a.out"
#SBATCH --mail-user=kayumovabduaziz@gmail.com
#SBATCH --mail-type=END,FAIL,TIME_LIMIT_80

SLURM_JOB_ID="$(squeue -u $LOGNAME |grep $HOSTNAME | awk '{print $1}')"
SCRATCH_DIR="/expanse/lustre/scratch/${USER}/temp_project"
mkdir -p "${SCRATCH_DIR}"

data_path="${SCRATCH_DIR}/$2"
gzip -dfc $1 > ${data_path}

dnf install wireshark-cli -y

python3.9 -m venv .env
source .env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -W ignore semiscan.py ${data_path} ${SCRATCH_DIR}