# Presidio-Based LLM Security Mini-Gateway
AIC201 - Assignment 2 | Bahria University

## What this does
A security gateway that protects LLM systems from prompt injection,
jailbreak attacks, and PII leakage using Microsoft Presidio.

## Pipeline
User Input → Injection Detection → Presidio PII Analysis → Policy Decision → Output

## Installation
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg

## Run
python gateway.py

## Reproduce Evaluation
Open demo.ipynb in Google Colab and run all cells top to bottom.

## Requirements
- Python 3.8+
- presidio-analyzer
- presidio-anonymizer
- spacy en_core_web_lg
- pandas
