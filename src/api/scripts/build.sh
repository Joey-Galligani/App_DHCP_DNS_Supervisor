#!/bin/bash

docker image rm sae501api
docker build -t sae501api:latest .
