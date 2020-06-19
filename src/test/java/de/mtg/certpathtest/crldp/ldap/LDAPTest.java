
package de.mtg.certpathtest.crldp.ldap;

import java.io.File;
import java.security.Security;

import org.apache.directory.api.util.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests basic functionality of the HTTP server like starting/stopping the server, starting /stopping the client and
 * writing a CRL.
 */
public class LDAPTest
{

    private static Logger logger = LoggerFactory.getLogger(LDAPTest.class);

    private static String workDirName = System.getProperty("java.io.tmpdir") + "/ldap-server-work";

    /**
     * Prepares the environment before every test.
     *
     * @throws Exception if any exception occurs.
     */
    @BeforeEach
    public void setUp() throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        File workDir = new File(workDirName);
        workDir.mkdirs();

        FileUtils.deleteDirectory(workDir);
        workDir.mkdirs();
    }

    /**
     * Tests basic functionality about LDAP like starting/stopping the server, starting /stopping the client and writing
     * a CRL.
     *
     * @throws Exception if any exception occurs.
     */
    @Test
    public void test()
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

            Assertions.assertNotNull(client);

            client.publishCRL(dn, "1234".getBytes());

            StringBuilder sb = new StringBuilder();

            client.createLDIF(leaf, sb, rootDN);

            Assertions.assertTrue(sb.length() != 0, "Could not create LDIF for node.");

            Assertions.assertTrue(sb.toString().indexOf("certificateRevocationList") != -1, "Did not publish CRL on node.");

            client.close();

        }
        catch (Exception e)
        {
            logger.error("", e);
            Assertions.fail("Error during starting/stopping LDAP server or/and connecting with the client.");
        }
    }

}
