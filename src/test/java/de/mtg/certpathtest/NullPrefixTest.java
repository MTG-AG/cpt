
package de.mtg.certpathtest;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.mtg.certpathtest.pkiobjects.Certificate;
import de.mtg.certpathtest.pkiobjects.Extension;
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
 * Simple units tests to check functionality of the null-prefix attack.
 */
public class NullPrefixTest
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
     * Tests whether the proper "Null" byte is present at the correct position and therefore render the attack possible.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void testNullIsPresent() throws Exception
    {
        Random random = new Random();

        String id = "JUNIT-" + random.nextInt(Integer.MAX_VALUE);

        Certificate xmlCertificate = new Certificate();

        xmlCertificate.setId(id);
        xmlCertificate.setIssuerDN(new IssuerDN("CN=Test Issuer, C=DE", "UTF8"));
        xmlCertificate.setSubjectDN(new SubjectDN("CN=Test User, C=DE", "UTF8"));
        xmlCertificate.setSerialNumber("1234567678");
        xmlCertificate.setVersion("2");
        xmlCertificate.setNotBefore(new NotBefore("-3D", "UTC"));
        xmlCertificate.setNotAfter(new NotAfter("+3D", "UTC"));
        xmlCertificate.setPublicKey(new PublicKey("RSA,2048", "pretty"));
        xmlCertificate.setSignature("1.2.840.113549.1.1.11"); // SHA256WithRSAEncryption
        xmlCertificate.setVerifiedBy(id);

        String rfc822Value = "a@a.de";
        String dnsValue = "ABCDEFG\0.HIJKLMN";

        String ipValue = "127.0.0.1";

        String sanValue = "rfc822Name=" + rfc822Value + ",dNSName=" + dnsValue + ",iPAddress=" + ipValue + "";

        xmlCertificate.getExtensions().add(new Extension(
                        sanValue,
                        "2.5.29.17",
                        "false",
                        "Subject Alternative Name",
                        "pretty"));

        TestToolCertificate technicalCertificate = new TestToolCertificate(xmlCertificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(technicalCertificate.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate asn1Certificate = (X509Certificate) cf.generateCertificate(bais);
        bais.close();

        X500Name issuer = new X500Name("CN=Test Issuer, C=DE");
        X500Name subject = new X500Name("CN=Test User, C=DE");

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                        issuer,
                        new BigInteger("1234567678"),
                        asn1Certificate.getNotBefore(),
                        asn1Certificate.getNotAfter(),
                        subject,
                        SubjectPublicKeyInfo.getInstance(asn1Certificate.getPublicKey()
                                                                        .getEncoded()));

        // Subject Alternative Name

        GeneralName[] generalNameArray = new GeneralName[3];
        generalNameArray[0] = new GeneralName(GeneralName.rfc822Name, rfc822Value);
        generalNameArray[1] = new GeneralName(GeneralName.dNSName, dnsValue);
        generalNameArray[2] = new GeneralName(GeneralName.iPAddress, ipValue);
        GeneralNames generalNames = new GeneralNames(generalNameArray);

        certificateGenerator.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                                          generalNames);

        // Starting signing

        PrivateKey privateKey = ObjectCache.getInstance().getPrivateKey(id);

        ContentSigner signer =
                        new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

        X509CertificateHolder certHolder = certificateGenerator.build(signer);
        X509Certificate highLevelCertificate =
                        new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        Assertions.assertTrue(Arrays.equals(asn1Certificate.getTBSCertificate(), highLevelCertificate.getTBSCertificate()));
        Assertions.assertTrue(Arrays.equals(asn1Certificate.getSignature(), highLevelCertificate.getSignature()));
        Assertions.assertTrue(Arrays.equals(asn1Certificate.getEncoded(), highLevelCertificate.getEncoded()));

        highLevelCertificate.verify(asn1Certificate.getPublicKey());
        asn1Certificate.verify(asn1Certificate.getPublicKey());
        Assertions.assertTrue(ByteArray.prettyPrint(asn1Certificate.getEncoded())
                                       .indexOf("41 42 43 44 45 46 47 00 2E 48 49 4A") != -1);

    }

}
