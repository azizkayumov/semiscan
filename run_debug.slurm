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
#SBATCH --output=".results/joblogs/semiscan-%A_%a.out"
#SBATCH --mail-user=kayumovabduaziz@gmail.com
#SBATCH --mail-type=END,FAIL,TIME_LIMIT_80

SLURM_JOB_ID="$(squeue -u $LOGNAME |grep $HOSTNAME | awk '{print $1}')"
JOB_OUTPUT_DIR=/expanse/lustre/projects/sds193/${USER}/semiscan/results/job_${SLURM_JOB_ID}
mkdir -p $JOB_OUTPUT_DIR
SCRATCH_DIR="/scratch/${USER}/job_${SLURM_JOB_ID}"

gzip -dfc $1 > $2

python3.9 -m venv .env
source .env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -W ignore semiscan.py $2 $3