
package de.mtg.certpathtest.crldp;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import javax.naming.NamingException;

import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.util.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.crldp.http.HTTPServerThread;
import de.mtg.certpathtest.crldp.ldap.LDAPClient;
import de.mtg.certpathtest.crldp.ldap.LDAPServerThread;

/**
 *
 * Objects of this class are used to deploy the servers (LDAP and HTTP) of the tool.
 *
 */
public class ServerMode
{

    private static Logger logger = LoggerFactory.getLogger(ServerMode.class);

    /**
     *
     * Constructs a newly allocated ServerMode object. Default constructor.
     *
     */
    public ServerMode()
    {

    }

    /**
     *
     * Starts the HTTP and/or LDAP server if this is configured. If hasWrite is true it deletes previous content for
     * LDAP and iterates over all <code>Location</code> elements and writes the CRL in the proper position. If hasWrite
     * is false then it only reads data that have been created probably in a previous run of the tool. USe hasWrite with
     * false if you operate the tool in server mode. In this mode new certificates or revocation lists are not created.
     *
     * @param hasWrite if true the tool writes data on the HTTP and/or LDAP server, otherwise it only reads existent
     *            data.
     */
    public void activate(boolean hasWrite)
    {

        ObjectCache objectCache = ObjectCache.getInstance();

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

        boolean useHTTP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.HTTP_USE);

        boolean windowStarted = false;

        if (useHTTP)
        {

            if (hasWrite)
            {

                ConcurrentHashMap<String, String> httpCRLDPs = objectCache.getHTTPCRLDPs();

                Enumeration<String> keys = httpCRLDPs.keys();

                while (keys.hasMoreElements())
                {

                    String crldp = keys.nextElement();

                    String crlId = httpCRLDPs.get(crldp);

                    byte[] rawCrl = objectCache.getRawCRL(crlId);

                    boolean httpExportSucceeded = writeCRLForHttp(crldp, rawCrl, crlId);

                    if (!httpExportSucceeded)
                    {
                        String message = "Could not export CRL '" + crlId + "' for the HTTP server.";
                        Utils.exitProgramm(message);
                    }
                }
            }

            Thread httpServerThread = new HTTPServerThread();
            httpServerThread.start();

            new StopApplicationWindow();

            windowStarted = true;

        }

        boolean useLDAP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.LDAP_USE);

        String resourcesDirectory =
            configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_RESOURCES_DIR);

        if (useLDAP)
        {

            ConcurrentHashMap<String, String> ldapCRLDPs = objectCache.getLDAPCRLDPs();

            Enumeration<String> keys = ldapCRLDPs.keys();

            if (hasWrite)
            {
                File workDir = new File(resourcesDirectory);

                if (!workDir.exists())
                {
                    workDir.mkdirs();
                }
                else
                {
                    try
                    {
                        FileUtils.deleteDirectory(workDir);
                    }
                    catch (IOException e)
                    {
                        Utils.logError("Could not delete resources directory for LDAP.");
                        logger.debug("", e);
                    }
                    workDir.mkdirs();
                }
            }
            else
            {

            }

            Thread ldapServerThread = new LDAPServerThread();
            ldapServerThread.start();

            String configuredHost =
                configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_HOST);
            String configuredPort =
                configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PORT);
            String configuredRoot =
                configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_ROOT_DN);
            String configuredLDAPPassword =
                configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PASSWORD);

            if (hasWrite)
            {
                int counter = 0;
                while (true)
                {
                    // attempted to connect 7 times, considering LDAP service not up.
                    if (counter > 7)
                    {
                        String message = "Could not connect to LDAP server.";
                        Utils.exitProgramm(message);
                        break;
                    }

                    LDAPClient client = null;

                    try
                    {
                        counter += 1;

                        client = new LDAPClient(
                                                configuredHost,
                                                    configuredPort,
                                                    configuredRoot,
                                                    "uid=admin,ou=system",
                                                    configuredLDAPPassword);

                        break;
                    }
                    catch (NamingException ne)
                    {
                        // LDAP is still not online, try in 2 seconds once again.
                        try
                        {
                            Thread.sleep(2000L);
                        }
                        catch (InterruptedException e)
                        {
                            logger.debug("", e);
                        }
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
                                logger.debug("", e.getMessage());
                            }
                        }
                    }
                }
            }

            if (hasWrite)
            {
                while (keys.hasMoreElements())
                {

                    String crldp = keys.nextElement();

                    String crlId = ldapCRLDPs.get(crldp);

                    byte[] rawCrl = objectCache.getRawCRL(crlId);

                    boolean ldapExportSucceeded = writeCRLForLDAP(crldp, rawCrl, crlId);

                    if (!ldapExportSucceeded)
                    {
                        String message = "Could not export CRL '" + crlId + "' for the LDAP server.";
                        Utils.exitProgramm(message);
                    }

                }
            }

            if (!windowStarted)
            {
                new StopApplicationWindow();
            }

            String archivesDirName = "archives";

            String timestamp = ObjectCache.getInstance().getArchiveTimestamp();

            if (hasWrite && useLDAP)
            {
                String filename = archivesDirName + System.getProperty("file.separator") + timestamp + "-LDAP.ldif";

                List<String> ldapEntries = objectCache.getLDAPEntries();
                StringBuilder ldifContent = new StringBuilder();
                String rootDN = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_ROOT_DN);
                LDAPClient client = null;
                try
                {
                    client = new LDAPClient(
                                            configuredHost,
                                                configuredPort,
                                                configuredRoot,
                                                "uid=admin,ou=system",
                                                configuredLDAPPassword);

                    client.createLDIF("", ldifContent, rootDN);

                    for (String ldapEntry : ldapEntries)
                    {
                        client.createLDIF(ldapEntry, ldifContent, rootDN);
                    }
                    Files.write(Paths.get(filename), ldifContent.toString().getBytes());

                }
                catch (NamingException | IOException e)
                {
                    Utils.logError("Could not archive data for LDAP.");
                    logger.debug("", e);
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
                            logger.debug("", e.getMessage());
                        }
                    }
                }

            }
        }

        if (hasWrite && useHTTP)
        {
            String archivesDirName = "archives";

            String timestamp = ObjectCache.getInstance().getArchiveTimestamp();

            String filename = archivesDirName + System.getProperty("file.separator") + timestamp + "-HTTP.zip";
            String resourcesDir =
                configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_RESOURCES_DIR);
            try
            {
                Utils.writeZip(filename, Paths.get(resourcesDir));
            }
            catch (IOException e)
            {
                Utils.logError("Could not archive data for HTTP.");
                logger.debug("", e);
            }
        }

        Path lockFile = Paths.get("cpt.lck");

        if (Files.exists(lockFile))
        {
            try
            {
                Files.delete(lockFile);
            }
            catch (IOException e)
            {
                logger.debug("Could not delete lock file", e);
            }
        }

        String name = ManagementFactory.getRuntimeMXBean().getName();

        try
        {
            Files.write(lockFile, name.getBytes());
        }
        catch (IOException e)
        {
            logger.debug("Could not touch lock file", e);
        }

        while (true)
        {
            try
            {
                Path currentDir = Paths.get(".");

                WatchService watcher = FileSystems.getDefault().newWatchService();
                WatchKey key = currentDir.register(watcher, StandardWatchEventKinds.ENTRY_DELETE);

                try
                {
                    key = watcher.take();

                    List<WatchEvent<?>> events = key.pollEvents();

                    for (WatchEvent<?> event : events)
                    {
                        Path file = (Path) event.context();

                        if (Files.isSameFile(lockFile, file))
                        {
                            logger.info("Stopping the application because the lock file has been deleted.");
                            logger.info("Program finished.");
                            Thread.sleep(1000L);
                            System.exit(0);
                        }

                    }

                }
                catch (InterruptedException ie)
                {
                    logger.debug("Error while scanning for the lock file.", ie);
                }

            }
            catch (IOException ioe)
            {
                logger.debug("Error while scanning for the lock file.", ioe);
            }

        }

    }

    private boolean writeCRLForHttp(String crldp, byte[] crl, String crlId)
    {
        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();
        String resourcesLocation =
            configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_RESOURCES_DIR);

        String host = "";
        String port = "";
        String path = "";
        String name = "";

        try
        {

            int startHost = crldp.indexOf("http://");

            int stopHost = crldp.indexOf(":", startHost + 6);
            int stopPort = crldp.indexOf("/", stopHost);
            int stopPath = crldp.indexOf("/", stopPort + 1);

            host = crldp.substring(startHost + 7, stopHost).trim();
            port = crldp.substring(stopHost + 1, stopPort).trim();
            path = crldp.substring(stopPort + 1, stopPath).trim();
            name = crldp.substring(stopPath + 1).trim();

        }
        catch (Exception e)
        {
            Utils.logError("Malformed HTTP URL for CRL with ID '" + crlId + "'.");
            return false;
        }

        if (StringUtils.isEmpty(host) || StringUtils.isEmpty(port) || StringUtils.isEmpty(path)
            || StringUtils.isEmpty(name))
        {
            Utils.logError("Malformed HTTP URL for CRL with ID '" + crlId + "'.");
            return false;
        }

        String configuredHost = configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_HOST);
        String configuredPort = configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_PORT);

        if (StringUtils.isEmpty(configuredHost) || StringUtils.isEmpty(configuredPort))
        {
            Utils.logError("Missing configuration parameter(s) '" + ConfigurationProperties.HTTP_HOST + "' or '"
                + ConfigurationProperties.HTTP_PORT + "'.");
            return false;
        }

        if (!StringUtils.equals(configuredHost, host))
        {
            logger.warn("Configured HTTP host '{}' and HTTP host '{}' for CRL '{}' do not match.", configuredHost, host,
                        crlId);
        }

        if (!StringUtils.equals(configuredPort, port))
        {
            logger.warn("Configured HTTP port '{}' and HTTP port '{}' for CRL '{}' do not match.", configuredPort, port,
                        crlId);
        }

        Path fileSystemPath = Paths.get(resourcesLocation, path);

        if (!fileSystemPath.toFile().exists())
        {
            fileSystemPath.toFile().mkdirs();
        }

        try
        {
            Files.write(Paths.get(resourcesLocation, path, name), crl);
        }
        catch (IOException e)
        {
            String message = "Could not export CRL '" + crlId + "' for HTTP.";
            Utils.logError(message);
            logger.debug("", e);
            return false;
        }

        return true;
    }

    private boolean writeCRLForLDAP(String crldp, byte[] crl, String crlId)
    {

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

        String host = "";
        String port = "";
        String path = "";
        String ldapSpecificData = "";

        String malformedCRLDPMessage = "Malformed LDAP URL '" + crldp + "' for CRL with ID '" + crlId + "'.";

        try
        {

            int startHost = crldp.indexOf("ldap://");

            int stopHost = crldp.indexOf(":", startHost + 6);
            int stopPort = crldp.indexOf("/", stopHost);
            int stopPath = crldp.indexOf("?", stopPort + 1);

            host = crldp.substring(startHost + 7, stopHost).trim();
            port = crldp.substring(stopHost + 1, stopPort).trim();
            path = crldp.substring(stopPort + 1, stopPath).trim();
            ldapSpecificData = crldp.substring(stopPath + 1).trim();
        }
        catch (Exception e)
        {
            Utils.logError(malformedCRLDPMessage);
            return false;
        }

        if (StringUtils.isEmpty(host) || StringUtils.isEmpty(port) || StringUtils.isEmpty(path)
            || StringUtils.isEmpty(ldapSpecificData))
        {
            Utils.logError(malformedCRLDPMessage);
            return false;
        }

        if (StringUtils.isEmpty(host) || StringUtils.isEmpty(port) || StringUtils.isEmpty(path)
            || StringUtils.isEmpty(ldapSpecificData))
        {
            Utils.logError(malformedCRLDPMessage);
            return false;
        }

        String configuredHost = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_HOST);
        String configuredPort = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PORT);
        String configuredRoot = configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_ROOT_DN);
        String configuredPassword =
            configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PASSWORD);

        if (StringUtils.isEmpty(configuredHost) || StringUtils.isEmpty(configuredPort)
            || StringUtils.isEmpty(configuredRoot))
        {
            Utils.logError("Missing configuration parameter(s) '" + ConfigurationProperties.LDAP_HOST + "' or '"
                + ConfigurationProperties.LDAP_PORT + "', or '" + ConfigurationProperties.LDAP_ROOT_DN + "'.");
            return false;
        }

        if (!crldp.toLowerCase().endsWith("certificaterevocationlist?base?objectclass=crldistributionpoint"))
        {
            Utils.logError("An LDAP URL must always end with 'certificateRevocationList?base?objectClass=cRLDistributionPoint'. Other values are not supported");
            return false;
        }

        if (!StringUtils.equals(configuredHost, host))
        {
            logger.warn("Configured LDAP host '{}' and LDAP host '{}' for CRL '{}' do not match.", configuredHost, host,
                        crlId);
        }

        if (!path.endsWith(configuredRoot))
        {
            Utils.logError("Path in the URL '" + path + "' and configured LDAP root '" + configuredRoot + "' for CRL '"
                + crlId + "' do not match.");
            return false;
        }

        if (!StringUtils.equals(configuredPort, port))
        {
            logger.warn("Configured LDAP port '{}' and LDAP port '{}' for CRL '{}' do not match.", configuredPort, port,
                        crlId);
        }

        try
        {

            LDAPClient client = new LDAPClient(host, port, configuredRoot, "uid=admin,ou=system", configuredPassword);

            client.publishCRL(path, crl);

            client.close();
        }
        catch (NamingException ne)
        {
            Utils.logError("Could not publish CRL in the directory.");
            logger.debug("", ne);
            return false;
        }

        return true;
    }

}
