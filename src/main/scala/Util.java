package nl.cleverbase.verify;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 * @author POReID
 */
public class Util {


    private static boolean isCertificateSelfSigned(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            PublicKey key = certificate.getPublicKey();
            certificate.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException ex) {
            return false;
        }
    }

    public static boolean isLeafCertificateValid(KeyStore kstore, X509Certificate cert) throws LeafCertificateValidationException {
        try {
            CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX");
            X509CertSelector select = new X509CertSelector();
            select.setSubject(cert.getSubjectX500Principal().getEncoded());

            Set trustanchors = new HashSet();
            List<Certificate> certList = new ArrayList<>();
            certList.add(cert);
            Enumeration<String> enumeration = kstore.aliases();
            while (enumeration.hasMoreElements()) {
                X509Certificate certificate = (X509Certificate) kstore.getCertificate(enumeration.nextElement());
                if (certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
                    if (isCertificateSelfSigned(certificate)) {
                        trustanchors.add(new TrustAnchor((X509Certificate) certificate, null));
                    }
                } else {
                    certList.add(certificate);
                }

            }

            PKIXBuilderParameters params = new PKIXBuilderParameters(trustanchors, select);
            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
            params.addCertStore(certStore);
            params.setRevocationEnabled(false);
            CertPathBuilderResult cpbr = pathBuilder.build(params);
            List<X509Certificate> path = (List<X509Certificate>) cpbr.getCertPath().getCertificates();
            X509Certificate issuer = (path.size()< 2 ? ((TrustAnchor)trustanchors.iterator().next()).getTrustedCert() : path.get(1));
            OCSPClient client = new OCSPClient(issuer, path.get(0));

            return client.checkOCSP();
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | OCSPValidationException | NoSuchProviderException | InvalidAlgorithmParameterException | CertPathBuilderException ex) {
            throw new LeafCertificateValidationException("Não foi possivel validar os dados enviados (" + ex.getMessage() + ")",ex);
        }
    }
}
