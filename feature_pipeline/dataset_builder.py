"""
Ilma — Dataset Builder
Converts captured PCAP / raw logs into labeled CSV for Kunal's training.
Usage: python feature_pipeline/dataset_builder.py --input data/raw/ --output data/processed/dataset.csv
"""
import argparse, pandas as pd, os

def build(input_dir: str, output_path: str):
    # TODO: Ilma — read PCAP files, extract features, label rows
    raise NotImplementedError("dataset_builder.py — Ilma to implement")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",  required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    build(args.input, args.output)
