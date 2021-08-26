#!/bin/sh

openssl x509 -outform der -in masterList.pem -out certificates.der
keytool -import -keystore cacerts -file certificates.der
