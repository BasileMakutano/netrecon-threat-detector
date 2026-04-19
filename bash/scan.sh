#!/bin/bash

mkdir -p ../data

TARGET="127.0.0.1"

nmap -sS -oN ../data/nmap.txt $TARGET