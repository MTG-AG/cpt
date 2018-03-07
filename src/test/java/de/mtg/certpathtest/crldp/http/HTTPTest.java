
package de.mtg.certpathtest.crldp.http;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Arrays;

import org.apache.directory.api.util.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.CertificateCreator;

/**
 *
 * Tests basic functionality of the HTTP server like starting/stopping the server, starting /stopping the client and
 * writing a CRL.
 *
 */
public class HTTPTest
{

    private static Logger logger = LoggerFactory.getLogger(HTTPTest.class);

    private static String workDirName = System.getProperty("java.io.tmpdir") + "/http-server-work";

    /**
     *
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @Before
    public void setUp() throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        File workDir = new File(workDirName);
        workDir.mkdirs();

        FileUtils.deleteDirectory(workDir);

        workDir.mkdirs();
    }

    /**
     *
     * Tests basic functionality of the HTTP server like starting/stopping the server, starting /stopping the client and
     * writing a CRL.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test() throws Exception
    {

        Server server = null;
        HttpClient httpClient = null;

        try
        {

            String httpHost = "localhost";
            String httpPort = "8099";

            server = new Server();
            ServerConnector serverConnector = new ServerConnector(server);
            serverConnector.setHost(httpHost);
            serverConnector.setPort(Integer.parseInt(httpPort));
            server.addConnector(serverConnector);

            ServletHandler servletHandler = new ServletHandler();
            server.setHandler(servletHandler);

            ResourceHandler resourceHandler = new ResourceHandler();

            resourceHandler.setDirectoriesListed(true);
            resourceHandler.setResourceBase(workDirName);

            HandlerList handlerList = new HandlerList();
            handlerList.setHandlers(new Handler[] {resourceHandler, new DefaultHandler()});
            server.setHandler(handlerList);

            X509CRL crl = CertificateCreator.getInstance().getCrl();

            Files.write(Paths.get(workDirName, "test.crl"), crl.getEncoded());

            try
            {
                server.start();
            }
            catch (Exception e)
            {
                logger.error("Could not start HTTP server. Please check if another instance of the server is running.");
                fail("Failed to start HTTP server.");
            }

            httpClient = null;

            httpClient = new HttpClient();
            httpClient.start();

            String url = "http://" + httpHost + ":" + httpPort + "/test.crl";

            byte[] readRawCrl = httpClient.GET(url).getContent();

            assertNotNull(readRawCrl);

            InputStream is = new ByteArrayInputStream(readRawCrl);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL readCrl = (X509CRL) cf.generateCRL(is);
            is.close();

            assertNotNull(readCrl);

            assertTrue(Arrays.equals(crl.getEncoded(), readRawCrl));

        }
        catch (Exception e)
        {
            logger.error("", e);
            fail("Error during starting/stopping HTTP server or/and connecting with the client.");
        }
        finally
        {
            if (httpClient != null)
            {

                httpClient.stop();
            }
            if (server != null)
            {

                server.stop();
            }

        }
    }

    /**
     *
     * Performs any necessary cleaning after each test run.
     *
     * @throws Exception if any exception occurs.
     */
    @After
    public void tearDown() throws Exception
    {
        File workDir = new File(workDirName);
        FileUtils.deleteDirectory(workDir);
    }
}
