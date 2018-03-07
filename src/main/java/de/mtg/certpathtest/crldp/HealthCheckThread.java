
package de.mtg.certpathtest.crldp;

import javax.naming.NamingException;
import javax.swing.ImageIcon;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.client.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.crldp.ldap.LDAPClient;

/**
 *
 * The thread to check whether the LDAP and/or HTTP server run and report this in the GUI.
 *
 */
public class HealthCheckThread extends Thread
{

    private static Logger logger = LoggerFactory.getLogger(HealthCheckThread.class);
    private StopApplicationWindow stopApplicationWindow;

    /**
     *
     * Constructs a newly allocated HealthCheckThread object.
     *
     * @param stopApplicationWindow the GUI window showing the health of the system. This is updated by this thread.
     */
    public HealthCheckThread(StopApplicationWindow stopApplicationWindow)
    {
        this.stopApplicationWindow = stopApplicationWindow;

    }

    /**
     *
     * {@inheritDoc}
     *
     * <p>
     * Checks periodically whether the LDAP or HTTP server run.
     */
    public void run()
    {

        while (true)
        {
            try
            {
                Thread.sleep(7000L);
            }
            catch (InterruptedException e)
            {
                logger.debug("", e);
            }

            LDAPClient client = null;

            ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();
            boolean useLDAP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.LDAP_USE);
            boolean useHTTP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.HTTP_USE);

            if (useLDAP)
            {
                String ldapHost = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_HOST);
                String ldapPort = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PORT);
                String ldapRoot =
                    configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_ROOT_DN);
                String ldapPassword =
                    configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PASSWORD);

                try
                {
                    client = new LDAPClient(ldapHost, ldapPort, ldapRoot, "uid=admin,ou=system", ldapPassword);

                    this.stopApplicationWindow.getLDAPStatus().setText("LDAP server is ON.");
                    this.stopApplicationWindow.getLDAPStatus().setIcon(new ImageIcon("resources/green.png"));

                }
                catch (Exception e)
                {
                    this.stopApplicationWindow.getLDAPStatus().setText("LDAP server is OFF.");
                    this.stopApplicationWindow.getLDAPStatus().setIcon(new ImageIcon("resources/red.png"));
                }
                finally
                {
                    if (client != null)
                    {
                        try
                        {
                            client.close();
                        }
                        catch (NamingException e)
                        {
                            logger.debug("", e);
                        }
                    }
                }
            }

            if (useHTTP)
            {
                String httpHost = "127.0.0.1";
                String httpPort = configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_PORT);

                HttpClient httpClient = null;
                try
                {

                    httpClient = new HttpClient();
                    httpClient.start();

                    String url = "http://" + httpHost + ":" + httpPort + "/";

                    String response = httpClient.GET(url).getContentAsString();

                    if (StringUtils.isNotEmpty(response))
                    {
                        this.stopApplicationWindow.getHTTPStatus().setText("HTTP server is ON");
                        this.stopApplicationWindow.getHTTPStatus().setIcon(new ImageIcon("resources/green.png"));
                    }
                    else
                    {
                        this.stopApplicationWindow.getHTTPStatus().setText("HTTP server is OFF.");
                        this.stopApplicationWindow.getHTTPStatus().setIcon(new ImageIcon("resources/red.png"));
                    }
                }
                catch (Exception e)
                {
                    logger.debug("", e);
                    this.stopApplicationWindow.getHTTPStatus().setText("HTTP server is OFF.");
                    this.stopApplicationWindow.getHTTPStatus().setIcon(new ImageIcon("resources/red.png"));
                }
                finally
                {
                    if (httpClient != null)
                    {
                        try
                        {
                            httpClient.stop();
                        }
                        catch (Exception e)
                        {
                            logger.debug("", e);
                        }
                    }
                }
            }

        }
    }

}
