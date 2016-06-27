#!/bin/bash
openssl genrsa -out key.key 2048
openssl req -new -x509 -days 3650 -key key.key -out cert.crt -subj "/"
