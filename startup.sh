#!/bin/bash
apt-get update
apt-get install -y libxmlsec1-dev libxmlsec1-openssl pkg-config
flask run