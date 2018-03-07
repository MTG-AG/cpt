
package de.mtg.certpathtest.crldp.ldap;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.Security;

import org.apache.directory.api.util.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Tests basic functionality of the HTTP server like starting/stopping the server, starting /stopping the client and
 * writing a CRL.
 *
 */
public class LDAPTest
{

    private static Logger logger = LoggerFactory.getLogger(LDAPTest.class);

    private static String workDirName = System.getProperty("java.io.tmpdir") + "/ldap-server-work";

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
     * Tests basic functionality about LDAP like starting/stopping the server, starting /stopping the client and writing
     * a CRL.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test() throws Exception
    {

        try
        {

            File workDir = new File(workDirName);

            // this is needed to avoid DEBUG messages from the apache DS library
            ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger("org.apache.directory")).setLevel(ch.qos.logback.classic.Level.WARN);
            ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger("org.apache.mina")).setLevel(ch.qos.logback.classic.Level.WARN);
            ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger("net.sf.ehcache")).setLevel(ch.qos.logback.classic.Level.WARN);

            // Create the server
            EmbeddedADSVerTrunk ads = new EmbeddedADSVerTrunk(workDir, "localhost", "10389", "dc=ldap-root");

            ads.startServer();

            String rootDN = "dc=ldap-root";
            String leaf = "CN=1,OU=1,O=1,C=DE,dc=test";
            String dn = leaf + "," + rootDN;

            LDAPClient client = new LDAPClient("localhost", "10389", rootDN, "uid=admin,ou=system", "secret");

            assertNotNull(client);

            client.publishCRL(dn, "1234".getBytes());

            StringBuilder sb = new StringBuilder();

            client.createLDIF(leaf, sb, rootDN);

            assertTrue("Could not create LDIF for node.", sb.length() != 0);

            assertTrue("Did not publish CRL on node.", sb.toString().indexOf("certificateRevocationList") != -1);

            client.close();


        }
        catch (Exception e)
        {
            logger.error("", e);
            fail("Error during starting/stopping LDAP server or/and connecting with the client.");
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

    }
}
