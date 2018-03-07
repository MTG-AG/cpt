
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
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads and tests the output of the test tool.
 *
 */
public class OutputReader extends SimpleFileVisitor<Path>
{

    String provider = null;

    /**
     *
     * Constructs a newly allocated OutputReader object.
     *
     * @param provider the name of the provider to use for the test.
     */
    public OutputReader(String provider)
    {

        this.provider = provider;
    }

    private static Logger logger = LoggerFactory.getLogger(OutputReader.class);

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

                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", this.provider);

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
                List<X509Certificate> caCertificates = new ArrayList<>();
                List<X509Certificate> sortedCaCertificates = new ArrayList<>();

                // Target Certificate
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

                for (Path path : directoryStream)
                {
                    InputStream is = Files.newInputStream(path);
                    caCertificates.add((X509Certificate) certificateFactory.generateCertificate(is));
                    is.close();
                }

                anchors.add(new TrustAnchor(trustAnchor, null));
                PKIXParameters params = new PKIXParameters(anchors);

                byte[] rawSubjectDN = trustAnchor.getSubjectX500Principal().getEncoded();

                int ref = sortedCaCertificates.size();

                while (sortedCaCertificates.size() != caCertificates.size())
                {

                    for (X509Certificate caCert : caCertificates)
                    {
                        if (Arrays.equals(caCert.getIssuerX500Principal().getEncoded(), rawSubjectDN))
                        {
                            sortedCaCertificates.add(caCert);
                            rawSubjectDN = caCert.getSubjectX500Principal().getEncoded();
                        }
                    }

                    if (ref + 1 != sortedCaCertificates.size())
                    {
                        System.err.println("More than one CA or none was found.");
                        break;
                    }

                    ref = sortedCaCertificates.size();
                }

                List<X509Certificate> certsBelongingToPath = new LinkedList<X509Certificate>();

                certsBelongingToPath.add(targetCertificate);

                counter = sortedCaCertificates.size();

                while (counter > 0)
                {

                    certsBelongingToPath.add(sortedCaCertificates.get(counter - 1));
                    counter -= 1;
                }

                CertPath certPath = certificateFactory.generateCertPath(certsBelongingToPath);
                params.setRevocationEnabled(false);
                params.setSigProvider(this.provider);
                CertPathValidator cpv = CertPathValidator.getInstance("PKIX", this.provider);
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