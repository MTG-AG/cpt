package de.mtg.certpathtest;



import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads and tests the output of the test tool.
 *
 */
public class OutputReaderPathConstruction extends SimpleFileVisitor<Path>
{

    private String provider = null;

    /**
     *
     * Constructs a newly allocated OutputReader object.
     *
     * @param provider the name of the provider to use for the test.
     */
    public OutputReaderPathConstruction(String provider)
    {

        this.provider = provider;
    }

    private static Logger logger = LoggerFactory.getLogger(OutputReaderPathConstruction.class);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult visitFile(Path file, BasicFileAttributes basicFileAttributes) throws IOException
    {

        return FileVisitResult.CONTINUE;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes basicFileAttributes) throws IOException
    {

        if (!("testOutput".equalsIgnoreCase(dir.getFileName().toString())
            || "crls".equalsIgnoreCase(dir.getFileName().toString())))
        {

            System.out.println("---------------------------------------------------------------------------------------------------------------------------------");
            try
            {
                Thread.sleep(300L);
            }
            catch (InterruptedException e1)
            {

            }
            System.out.println("Working on: " + dir.getFileName());
            try
            {

                CertificateFactory certificateFactory = null;
                if (this.provider == null)
                {

                    certificateFactory = CertificateFactory.getInstance("X.509");
                }
                else
                {
                    certificateFactory = CertificateFactory.getInstance("X.509", this.provider);
                }

                Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();

                PathMatcher trustAnchorMatcher = FileSystems.getDefault().getPathMatcher("glob:*.TA.crt");
                PathMatcher targetCertificateMatcher = FileSystems.getDefault().getPathMatcher("glob:*.TC.crt");
                PathMatcher caCertificateMatcher = FileSystems.getDefault().getPathMatcher("glob:*.CA.crt");

                DirectoryStream.Filter<Path> trustAnchorFilter = new DirectoryStream.Filter<Path>()
                {
                    public boolean accept(Path file) throws IOException
                    {
                        return (file.getFileName() != null && trustAnchorMatcher.matches(file.getFileName()));
                    }
                };

                DirectoryStream.Filter<Path> targetCertificateFilter = new DirectoryStream.Filter<Path>()
                {
                    public boolean accept(Path file) throws IOException
                    {
                        return (file.getFileName() != null && targetCertificateMatcher.matches(file.getFileName()));
                    }
                };

                DirectoryStream.Filter<Path> caCertificateFilter = new DirectoryStream.Filter<Path>()
                {
                    public boolean accept(Path file) throws IOException
                    {
                        return (file.getFileName() != null && caCertificateMatcher.matches(file.getFileName()));
                    }
                };

                X509Certificate trustAnchor = null;
                X509Certificate targetCertificate = null;

                DirectoryStream<Path> directoryStream = Files.newDirectoryStream(dir, trustAnchorFilter);
                int counter = 0;
                for (Path path : directoryStream)
                {
                    counter += 1;
                    InputStream is = Files.newInputStream(path);
                    trustAnchor = (X509Certificate) certificateFactory.generateCertificate(is);
                    is.close();
                }

                if (counter != 1)
                {
                    System.err.println("More than one trust anchor were found in directory");
                }

                // Target Certificate

                directoryStream = Files.newDirectoryStream(dir, targetCertificateFilter);
                counter = 0;
                for (Path path : directoryStream)
                {
                    counter += 1;
                    InputStream is = Files.newInputStream(path);
                    targetCertificate = (X509Certificate) certificateFactory.generateCertificate(is);
                    is.close();
                }

                if (counter != 1)
                {
                    System.err.println("More than one target certificate were found in directory");
                }

                // CA Certificates

                directoryStream = Files.newDirectoryStream(dir, caCertificateFilter);

                ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
                for (Path path : directoryStream)
                {
                    InputStream is = Files.newInputStream(path);
                    certs.add((X509Certificate) certificateFactory.generateCertificate(is));
                    is.close();
                }

                anchors.add(new TrustAnchor(trustAnchor, null));
                PKIXParameters params = new PKIXParameters(anchors);

                certs.add(targetCertificate);

                CollectionCertStoreParameters certStoreParams = new CollectionCertStoreParameters(certs);
                CertStore certStore = CertStore.getInstance("Collection", certStoreParams);

                X509CertSelector certSelector = new X509CertSelector();
                certSelector.setCertificate(targetCertificate);
                certSelector.setSubject(targetCertificate.getSubjectDN().getName());

                CertPathBuilder certPathBuilder = null;

                if (this.provider == null)
                {
                    certPathBuilder = CertPathBuilder.getInstance("PKIX");
                }
                else
                {
                    certPathBuilder = CertPathBuilder.getInstance("PKIX", this.provider);
                }

                PKIXBuilderParameters certPathBuilderParams = new PKIXBuilderParameters(anchors, certSelector);
                certPathBuilderParams.addCertStore(certStore);
                certPathBuilderParams.setRevocationEnabled(false);
                CertPathBuilderResult cpbResult = certPathBuilder.build(certPathBuilderParams);

                CertPath certPath = cpbResult.getCertPath();

                params.setRevocationEnabled(false);

                CertPathValidator cpv = null;

                if (this.provider == null)
                {
                    cpv = CertPathValidator.getInstance("PKIX");
                }
                else
                {
                    params.setSigProvider(this.provider);
                    cpv = CertPathValidator.getInstance("PKIX", this.provider);
                }

                PKIXCertPathValidatorResult certPathValidatorResult =
                    (PKIXCertPathValidatorResult) cpv.validate(certPath, params);

                System.out.println(certPathValidatorResult.getPublicKey());
                System.out.println(certPathValidatorResult.getPolicyTree());

            }
            catch (Exception e)
            {
                e.printStackTrace();
                try
                {
                    Thread.sleep(300L);
                }
                catch (InterruptedException e1)
                {

                }
            }

            PathMatcher reportMatcher = FileSystems.getDefault().getPathMatcher("glob:testReport.txt");

            DirectoryStream.Filter<Path> reportFilter = new DirectoryStream.Filter<Path>()
            {
                public boolean accept(Path file) throws IOException
                {
                    return file.getFileName() != null && reportMatcher.matches(file.getFileName());
                }
            };

            DirectoryStream<Path> directoryStream = Files.newDirectoryStream(dir, reportFilter);
            for (Path path : directoryStream)
            {
                String content = new String(Files.readAllBytes(path));
                System.out.println(content);
            }

        }

        return FileVisitResult.CONTINUE;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult postVisitDirectory(Path dir, IOException ioe)
    {
        return FileVisitResult.CONTINUE;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult visitFileFailed(Path file, IOException ioe)
    {
        logger.error("Could not read file '{}'.", file.toString());
        return FileVisitResult.CONTINUE;
    }

}