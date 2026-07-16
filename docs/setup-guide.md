# Setup Guide

## Environment

This project was developed and tested in a Kali Linux virtual machine.

## Prerequisites

- Kali Linux or another compatible Linux distribution
- Python 3
- pip
- OpenCanary
- Ollama
- A locally available Ollama model

## Create a Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config/opencanary.conf.example ~/.opencanary.conf
opencanaryd --start
tail -f /var/tmp/opencanary.log
ollama list
python3 src/intrusion_analyzer.py
