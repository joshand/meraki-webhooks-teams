#!/bin/bash

# pull down docker image
docker pull joshand/meraki-webhooks-teams

# make sure docker image is not already running
docker-compose down

# start docker image
docker-compose up