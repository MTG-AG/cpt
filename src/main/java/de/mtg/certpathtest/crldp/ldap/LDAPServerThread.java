
package de.mtg.certpathtest.crldp.ldap;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.Utils;

/**
 *
 * The thread where the LDAP server for the revocation list distribution runs.
 *
 */
public class LDAPServerThread extends Thread
{

    private static Logger logger = LoggerFactory.getLogger(LDAPServerThread.class);

    /**
     *
     * {@inheritDoc}
     */
    public void run()
    {

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

        String host = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_HOST);

        String port = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PORT);

        String rootDN = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_ROOT_DN);

        String resourcesDirectory =
            configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_RESOURCES_DIR);

        try
        {
            File workDir = new File(resourcesDirectory);

            EmbeddedADSVerTrunk ldapServer = new EmbeddedADSVerTrunk(workDir, host, port, rootDN);

            ldapServer.startServer();
        }
        catch (Exception e)
        {
            Utils.logError("Could not start LDAP Server. Please check if another instance of the server is running.");
            logger.debug("", e);
        }

    }

}
