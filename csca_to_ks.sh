#!/usr/bin/env bash

################################################################################
# Script to convert a CSCA masterlist into a Java keystore
#
# Usage: ./csca_to_ks.sh <masterlist>
#           - masterlist: the CMS message containing the masterlist
################################################################################

CMS_MESSAGE=$1

# Verify ML signature and extract ML from CMS message
openssl cms -in "${CMS_MESSAGE}" -inform der -no_signer_cert_verify -verify -out "${CMS_MESSAGE}.der" -certsout signing.pem || exit 1

# Split ML into individual certificates
eval $(openssl asn1parse -in "${CMS_MESSAGE}.der" -inform der -i | \
       awk "/:d=1/{b=0}
            /:d=1.*SET/{b=1}
	        /:d=2/&&b{print}" |\
       sed 's/^ *\([0-9]*\).*hl= *\([0-9]*\).*l= *\([0-9]*\).*/ \
	     dd if="${CMS_MESSAGE}.der" bs=1 skip=\1 count=$((\2+\3)) 2>\/dev\/null | openssl x509 -inform der -out cert.\1.pem -outform pem;/')

for cert in cert.*.pem; do
	keytool -alias ${cert} -importcert -noprompt -file ${cert} -keystore masterlist.bks -storepass changeit -storetype BKS \
	         -providerClass org.bouncycastle.jce.provider.BouncyCastleProvider \
	         -providerpath bcprov-jdk16-1.46.jar && rm ${cert}
done