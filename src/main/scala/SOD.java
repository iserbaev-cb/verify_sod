/*
 * The MIT License
 *
 * Copyright 2014 Rui Martinho (rmartinho@gmail.com), António Braz (antoniocbraz@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package nl.cleverbase.verify;

import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author POReID
 */
public class SOD {

    private final CMSSignedData cms;
    private final LDSSecurityObject lds;
    private final KeyStore keystore;

    protected SOD(byte[] sod, KeyStore keystore) throws Exception {
        try {
            cms = new CMSSignedData(sod);
            lds = LDSSecurityObject.getInstance(cms.getSignedContent().getContent());
            this.keystore = keystore;
        } catch (CMSException ex) {
            throw new Exception("não foi possivel instanciar o SOD", ex);
        }
    }


    private boolean isCertificateSelfSigned(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            PublicKey key = certificate.getPublicKey();
            certificate.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException ex) {
            return false;
        }
    }


    protected boolean verify() throws Exception {
        try {
            X509CertificateHolder holder = (X509CertificateHolder) cms.getCertificates().getMatches(null).iterator().next();
            X509Certificate cert = (X509Certificate) get(holder.getEncoded());

            SignerInformationStore signerInformationStore = cms.getSignerInfos();
            SignerInformation signerInformation = (SignerInformation) signerInformationStore.getSigners().iterator().next(); // apenas 1 assinatura (só tem 1)

//            if (!Util.isLeafCertificateValid(keystore, cert)) {
//                return false;
//            }

            /* verificar assinatura do cms */
            ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(cert);
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(new BouncyCastleProvider()).build();
            SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
            CMSSignatureAlgorithmNameGenerator signatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
            SignerInformationVerifier signerInformationVerifier = new SignerInformationVerifier(signatureAlgorithmNameGenerator, signatureAlgorithmIdentifierFinder, contentVerifierProvider, digestCalculatorProvider);

            return signerInformation.verify(signerInformationVerifier);

        } catch (IOException | CertificateException | OperatorCreationException | CMSException ex) {
            System.out.println(ex);
            throw new Exception("Não foi possivel verificar o SOD (" + ex.getMessage() + ")", ex);
        }
    }


    private Certificate get(final byte[] bytes) throws CertificateException, NoSuchProviderException {
        return CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new ByteArrayInputStream(bytes));
    }


    protected byte[] getCitizenIdentificationHash() {
        return lds.getDatagroupHash()[0].getDataGroupHashValue().getOctets();
    }


    protected byte[] getCitizenAddressHash() {
        return lds.getDatagroupHash()[1].getDataGroupHashValue().getOctets();
    }


    protected byte[] getCitizenPhoto() {
        return lds.getDatagroupHash()[2].getDataGroupHashValue().getOctets();
    }


    protected byte[] getCitizenPublicKeyHash() {
        return lds.getDatagroupHash()[3].getDataGroupHashValue().getOctets();
    }
}
