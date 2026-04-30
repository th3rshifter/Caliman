#!/bin/bash
set -e

curl -f http://localhost:8080/health
curl -f http://localhost:8080/ready

kubectl get pods -n caliman