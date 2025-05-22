# obscura/cli.py

from .main import main as obscura_main

def main():
    # Entry point that setuptools can hook into
    obscura_main()
