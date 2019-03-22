#!/bin/bash
set -x
kubectl delete -f deployment/deployment.yaml
kubectl delete -f deployment/mutatingwebhook-ca-bundle.yaml
cat deployment/mutatingwebhook.yaml |  deployment/webhook-patch-ca-bundle.sh > deployment/mutatingwebhook-ca-bundle.yaml
kubectl create -f deployment/mutatingwebhook-ca-bundle.yaml
kubectl create -f deployment/deployment.yaml
kubectl get pods
