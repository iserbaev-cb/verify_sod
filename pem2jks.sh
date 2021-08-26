#!/bin/bash
pemToJks()
{
        # number of certs in the PEM file
        pemCerts=$1
        certPass=$2
        newCert=$(basename "$pemCerts")
        newCert="${newCert%%.*}"
        newCert="${newCert}"".JKS"
        ##echo $newCert $pemCerts $certPass
        CERTS=$(grep 'END CERTIFICATE' $pemCerts| wc -l)
        echo $CERTS
        # For every cert in the PEM file, extract it and import into the JKS keystore
        # awk command: step 1, if line is in the desired cert, print the line
        #              step 2, increment counter when last line of cert is found
        for N in $(seq 0 $(($CERTS - 1))); do
          ALIAS="${pemCerts%.*}-$N"
          cat $pemCerts |
                awk "n==$N { print }; /END CERTIFICATE/ { n++ }" |
                keytool -noprompt -import -trustcacerts \
                                -alias $ALIAS -keystore $newCert -storepass $certPass
                keytool -alias $ALIAS -importcert -noprompt -file ${cert} -keystore $newCert -storepass $certPass \
                                -storetype BKS -providerClass org.bouncycastle.jce.provider.BouncyCastleProvider
        done
}
pemToJks masterList.pem masterList.jks
