#!/bin/bash

docker stop sae501api
sleep 2
docker run --rm -p 8000:80 --name sae501api -d sae501api:latest
