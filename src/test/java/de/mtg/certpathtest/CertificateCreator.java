
package de.mtg.certpathtest;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 *
 * Help class for dynamically creating certificates for the unit tests.
 *
 */
public class CertificateCreator
{

    private static CertificateCreator certificateCreator;

    private static final Provider BC = new BouncyCastleProvider();

    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_ECDSA = "ECDSA";

    private X509Certificate eeCertificate;

    private X509Certificate subCACertificate;

    private X509Certificate rootCACertificate;

    private PrivateKey rootCAPrivateKey;

    private PrivateKey subCAPrivateKey;

    private PrivateKey eePrivateKey;

    private X509CRL crl;

    static
    {
        Security.addProvider(BC);

    }

    /**
     *
     * Constructs a newly allocated CertificateCreator object.
     *
     * @throws NoSuchAlgorithmException if the required algorithms are not implemented by an installed JCA provider.
     * @throws CertIOException if encoding problem during certificate creation occur.
     * @throws OperatorCreationException if errors during signing occur.,
     * @throws CertificateException if encoding problem during certificate creation occur.
     * @throws InvalidAlgorithmParameterException if the parameters of an algorithm are invalid, for example the
     *             unlimited strength of JCA/JCE is not installed.
     * @throws CRLException if encoding problem during CRL creation occur.
     */
    private CertificateCreator() throws NoSuchAlgorithmException, CertIOException, OperatorCreationException,
                                 CertificateException, InvalidAlgorithmParameterException, CRLException
    {

        // create Root

        BigInteger sn = BigInteger.ONE;

        Date now = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.HOUR, -4);
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date notAfter = calendar.getTime();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM_RSA, BC);
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        rootCAPrivateKey = kp.getPrivate();
        PublicKey rootPublicKey = kp.getPublic();

        X500Name x500 = new X500Name("CN=Test Root, C=DE");
        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(
                                                                                     x500,
                                                                                         sn,
                                                                                         notBefore,
                                                                                         notAfter,
                                                                                         x500,
                                                                                         SubjectPublicKeyInfo.getInstance(rootPublicKey.getEncoded()));

        JcaX509ExtensionUtils util = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier aki = util.createAuthorityKeyIdentifier(kp.getPublic());
        SubjectKeyIdentifier ski = util.createSubjectKeyIdentifier(kp.getPublic());

        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, aki);
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, ski);
        certificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        DistributionPointName dpn = null;

        dpn = new DistributionPointName(new GeneralNames(
                                                         new GeneralName(
                                                                         GeneralName.uniformResourceIdentifier,
                                                                             "http://" + "rootca")));

        DistributionPoint[] distPoints = new DistributionPoint[1];
        distPoints[0] = new DistributionPoint(dpn, null, null);
        certificateGenerator.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints));

        ContentSigner rsaSigner =
            new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(rootCAPrivateKey);

        X509CertificateHolder certHolder = certificateGenerator.build(rsaSigner);
        rootCACertificate = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHolder);

        // create SubCA

        sn = sn.add(BigInteger.ONE);
        Date issuerNB = rootCACertificate.getNotBefore();

        calendar.setTime(issuerNB);
        calendar.add(Calendar.HOUR, 1);
        notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        notAfter = calendar.getTime();

        ECParameterSpec ecps = ECNamedCurveTable.getParameterSpec("prime256v1");
        kpg = KeyPairGenerator.getInstance(ALGORITHM_ECDSA, BC);
        kpg.initialize(ecps);
        kp = kpg.generateKeyPair();

        subCAPrivateKey = kp.getPrivate();
        PublicKey subCAPublicKey = kp.getPublic();

        certificateGenerator = new X509v3CertificateBuilder(
                                                            new X500Name(rootCACertificate.getSubjectDN().getName()),
                                                                sn,
                                                                notBefore,
                                                                notAfter,
                                                                new X500Name("CN=Test SubCA, C=DE"),
                                                                SubjectPublicKeyInfo.getInstance(subCAPublicKey.getEncoded()));

        util = new JcaX509ExtensionUtils();
        aki = util.createAuthorityKeyIdentifier(rootCACertificate.getPublicKey());
        ski = util.createSubjectKeyIdentifier(subCAPublicKey);

        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, true, aki);
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, ski);
        certificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        rsaSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(rootCAPrivateKey);

        certHolder = certificateGenerator.build(rsaSigner);

        subCACertificate = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHolder);

        // create EE

        sn = sn.add(BigInteger.ONE);
        issuerNB = subCACertificate.getNotBefore();

        calendar.setTime(issuerNB);
        calendar.add(Calendar.HOUR, 1);
        notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        notAfter = calendar.getTime();

        kp = kpg.generateKeyPair();
        eePrivateKey = kp.getPrivate();
        PublicKey eePublicKey = kp.getPublic();

        certificateGenerator = new X509v3CertificateBuilder(
                                                            new X500Name(subCACertificate.getSubjectDN().getName()),
                                                                sn,
                                                                notBefore,
                                                                notAfter,
                                                                new X500Name("CN=Test EE, C=DE"),
                                                                SubjectPublicKeyInfo.getInstance(eePublicKey.getEncoded()));

        util = new JcaX509ExtensionUtils();
        aki = util.createAuthorityKeyIdentifier(subCACertificate.getPublicKey());
        ski = util.createSubjectKeyIdentifier(eePublicKey);

        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, true, aki);
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, ski);
        certificateGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner ecSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(subCAPrivateKey);

        certHolder = certificateGenerator.build(ecSigner);

        eeCertificate = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHolder);

        // create CRL

        X509v2CRLBuilder crlBuilder =
            new X509v2CRLBuilder(new X500Name(rootCACertificate.getSubjectDN().getName()), now);

        crlBuilder.setNextUpdate(notAfter);

        crlBuilder.addCRLEntry(eeCertificate.getSerialNumber(), now, null);

        X509CRLHolder crlHolder = crlBuilder.build(rsaSigner);
        crl = new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

    }

    /**
     *
     * Creates a minimal PKI hierarchy of a Root-CA signing the certificate of a Sub-CA which signs and end-entity
     * certificate. It also creates a CRL signed by the Root-CA. These certificates and CRLs are used by the tests.
     *
     * @return a PKI hierarchy containing certificates and a CRL.
     * @throws NoSuchAlgorithmException if the required algorithms are not implemented by an installed JCA provider.
     * @throws CertIOException if encoding problem during certificate creation occur.
     * @throws OperatorCreationException if errors during signing occur.,
     * @throws CertificateException if encoding problem during certificate creation occur.
     * @throws InvalidAlgorithmParameterException if the parameters of an algorithm are invalid, for example the
     *             unlimited strength of JCA/JCE is not installed.
     * @throws CRLException if encoding problem during CRL creation occur.
     */
    public static CertificateCreator getInstance() throws NoSuchAlgorithmException, CertIOException,
                    OperatorCreationException, CertificateException, CRLException, InvalidAlgorithmParameterException
    {
        if (certificateCreator == null)
        {
            synchronized (CertificateCreator.class)
            {
                if (certificateCreator == null)
                {
                    certificateCreator = new CertificateCreator();
                }
            }
        }
        return certificateCreator;
    }

    /**
     *
     * The certificate of an end-entity signed by the Sub-CA.
     *
     * @return the certificate of the end-entity.
     */
    public X509Certificate getEeCertificate()
    {
        return eeCertificate;
    }

    /**
     *
     * The certificate of the Sub-CA signed by the Root-CA.
     *
     * @return the certificate of the Sub-CA.
     */
    public X509Certificate getSubCACertificate()
    {
        return subCACertificate;
    }

    /**
     *
     * The self-signed certificate of the Root-CA.
     *
     * @return the self-signed certificate of the Root-CA.
     */
    public X509Certificate getRootCACertificate()
    {
        return rootCACertificate;
    }

    /**
     *
     * Returns the private key of the Root-CA for using it in tests while creating certificates.
     *
     * @return the private key of the Root-CA.
     */
    public PrivateKey getRootCAPrivateKey()
    {
        return rootCAPrivateKey;
    }

    /**
     *
     * Returns the private key of the Sub-CA for using it in tests while creating certificates.
     *
     * @return the private key of the Sub-CA.
     */
    public PrivateKey getSubCAPrivateKey()
    {
        return subCAPrivateKey;
    }

    /**
     *
     * Returns the private key of the end-entity for using it in tests while creating certificates.
     *
     * @return the private key of the end-entity.
     */
    public PrivateKey getEePrivateKey()
    {
        return eePrivateKey;
    }

    /**
     *
     * Returns the revocation list of the Root-CA.
     *
     * @return the revocation list of the Root-CA.
     */
    public X509CRL getCrl()
    {
        return crl;
    }

}
