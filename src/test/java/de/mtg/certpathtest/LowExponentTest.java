
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.IssuerDN;
import de.mtg.certpathtest.pkiobjects.NotAfter;
import de.mtg.certpathtest.pkiobjects.NotBefore;
import de.mtg.certpathtest.pkiobjects.PublicKey;
import de.mtg.certpathtest.pkiobjects.SubjectDN;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Units tests for the Low Exponent modification.
 */
public class LowExponentTest
{

    /**
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeAll
    public static void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Tests whether the calculated signature from the tool matches a signature calculated by the provider. If this is
     * successful then the manipulated value is most probably calculated also correctly.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testOwnSignature() throws Exception
    {

        calculateSignatures("1.2.840.113549.1.1.5", 512); // SHA1
        calculateSignatures("1.2.840.113549.1.1.14", 512); // SHA224
        calculateSignatures("1.2.840.113549.1.1.11", 512); // SHA256
        calculateSignatures("1.2.840.113549.1.1.12", 512); // SHA384
        calculateSignatures("1.2.840.113549.1.1.13", 512); // SHA512

        calculateSignatures("1.2.840.113549.1.1.5", 1024); // SHA1
        calculateSignatures("1.2.840.113549.1.1.14", 1024); // SHA224
        calculateSignatures("1.2.840.113549.1.1.11", 1024); // SHA256
        calculateSignatures("1.2.840.113549.1.1.12", 1024); // SHA384
        calculateSignatures("1.2.840.113549.1.1.13", 1024); // SHA512

    }

    private void calculateSignatures(String oid, int pLength) throws Exception
    {

        for (int i = 0; i < 2; i++)
        {

            Random random = new Random();

            String id = "JUnit-" + random.nextInt(Integer.MAX_VALUE);

            BigInteger e;
            BigInteger n;
            BigInteger d;

            while (true)
            {
                BigInteger p = new BigInteger(pLength, 80, new Random());
                BigInteger q = new BigInteger(pLength, 80, new Random());

                e = new BigInteger("3");
                n = p.multiply(q);
                BigInteger phip = p.subtract(BigInteger.ONE);
                BigInteger phiq = q.subtract(BigInteger.ONE);
                BigInteger phin = phip.multiply(phiq);

                try
                {
                    d = e.modInverse(phin);
                    break;
                }
                catch (ArithmeticException ae)
                {

                }
            }

            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);

            RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);

            String encodedPublicKey = new String(Base64.encode(rsaPublicKey.getEncoded()));

            String encodedPrivateKey = new String(Base64.encode(rsaPrivateKey.getEncoded()));

            String xmlKey = encodedPublicKey + "|" + encodedPrivateKey;

            Certificate xmlCertificate = new Certificate();

            xmlCertificate.setId(id);
            xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
            xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
            xmlCertificate.setSerialNumber(new BigInteger(32, new Random()).toString());
            xmlCertificate.setVersion("2");
            xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
            xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
            xmlCertificate.setPublicKey(new PublicKey(xmlKey, "raw"));
            xmlCertificate.setSignature(oid);
            xmlCertificate.setVerifiedBy(id);

            TestToolCertificate certificate = new TestToolCertificate(xmlCertificate);

            ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
            bais.close();

            byte[] signature = cert.getSignature();
            byte[] tbsCertificate = cert.getTBSCertificate();

            Signature jcaSignature = Signature.getInstance(oid, "BC");
            jcaSignature.initSign(rsaPrivateKey);
            jcaSignature.update(tbsCertificate);
            byte[] newSignature = jcaSignature.sign();
            Assertions.assertTrue(Arrays.equals(signature, newSignature));

            byte[] calculatedSignature = Utils.calculateBleichenbacherSignature(tbsCertificate, 0, d, n, oid);

            Assertions.assertTrue(Arrays.equals(calculatedSignature, newSignature));
        }

    }

}