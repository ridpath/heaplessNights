#!/bin/bash
cd /home/over/projects/offsec-jenkins
export PATH="/home/over/.local/bin:$PATH"
pytest tests/ -v
