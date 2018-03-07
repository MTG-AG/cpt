
package de.mtg.certpathtest;

import java.util.Hashtable;
import java.util.Iterator;

import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.BasicConfigurationBuilder;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.convert.DefaultListDelimiterHandler;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigurationProperties
{

    private static Logger logger = LoggerFactory.getLogger(ConfigurationProperties.class);

    private PropertiesConfiguration properties = new PropertiesConfiguration();

    private static ConfigurationProperties configurationProperties;

    public static String OUTPUT_DIRECTORY_PROPERTY = "output.directory";
    public static String REPORT_TEMPLATE_FILENAME = "report.template.filename";
    public static String REPORT_TEST_OBJECT_NAME = "report.testobject.name";
    public static String REPORT_TEST_OBJECT_VERSION = "report.testobject.version";
    public static String PKI_OBJECTS_INPUT_DIRECTORY = "pkiobjects.input.directory";
    public static String SETUP_PKI_OBJECTS_INPUT_DIRECTORY = "setup.pkiobjects.input.directory";
    public static String SETUP_OUTPUT_DIRECTORY_PROPERTY = "setup.output.directory";


    public static String SKIP_TEST_CASES = "skipTestCases";
    public static String PROFILES_TO_RUN = "profiles";

    /* HTTP section */

    public static String HTTP_USE = "http.use";
    public static String HTTP_HOST = "http.host";
    public static String HTTP_PORT = "http.port";
    public static String HTTP_RESOURCES_DIR = "http.resources.directory";

    /* LDAP section */

    public static String LDAP_USE = "ldap.use";
    public static String LDAP_HOST = "ldap.host";
    public static String LDAP_PORT = "ldap.port";
    public static String LDAP_ROOT_DN = "ldap.root";
    public static String LDAP_PASSWORD = "ldap.password";
    public static String LDAP_RESOURCES_DIR = "ldap.resources.directory";

    public static String SHOW_GUI = "showGUI";

    /* Email section */

    public static String EMAIL_SMTP_USE = "email.smtp.use";
    public static String EMAIL_SMTP_HOST = "email.smtp.host";
    public static String EMAIL_SMTP_PORT = "email.smtp.port";
    public static String EMAIL_SENDER = "email.sender";
    public static String EMAIL_RECIPIENT = "email.recipient";
    public static String EMAIL_SMIME_SIGNATURE_ALGORITHM = "email.signature.algorithm";



    private ConfigurationProperties()
    {

    }

    public static ConfigurationProperties getInstance()
    {
        if (configurationProperties == null)
        {
            synchronized (ConfigurationProperties.class)
            {
                if (configurationProperties == null)
                {
                    configurationProperties = new ConfigurationProperties();
                }
            }
        }
        return configurationProperties;
    }

    public void init(String propertiesFilename) throws ConfigurationException
    {

        FileBasedConfigurationBuilder<PropertiesConfiguration> builder =
            new FileBasedConfigurationBuilder<PropertiesConfiguration>(PropertiesConfiguration.class).configure(new Parameters().properties()
                                                                                                                                .setFileName(propertiesFilename)
                                                                                                                                .setThrowExceptionOnMissing(true)
                                                                                                                                .setListDelimiterHandler(new DefaultListDelimiterHandler(';'))
                                                                                                                                .setIncludesAllowed(false));
        this.properties = builder.getConfiguration();

    }

    public PropertiesConfiguration getProperties()
    {
        return properties;
    }

    public void addSimpleProperty(String propertyName, String propertyValue)
    {
        if (getProperties() == null)
        {

            BasicConfigurationBuilder<PropertiesConfiguration> builder =
                new BasicConfigurationBuilder<PropertiesConfiguration>(PropertiesConfiguration.class).configure(new Parameters().properties()
                                                                                                                                .setThrowExceptionOnMissing(true)
                                                                                                                                .setListDelimiterHandler(new DefaultListDelimiterHandler(';'))
                                                                                                                                .setIncludesAllowed(false));
            try
            {
                this.properties = builder.getConfiguration();
            }
            catch (ConfigurationException e)
            {
                Utils.logError(" "+e);
                logger.debug("", e);
            }

        }
        getProperties().addProperty(propertyName, propertyValue);
    }

    public Hashtable<String, String> getReplacementProperties()
    {

        Hashtable<String, String> result = new Hashtable<String, String>();
        PropertiesConfiguration propertiesConfiguration = getProperties();
        Iterator<String> propertyKeys = propertiesConfiguration.getKeys();

        while (propertyKeys.hasNext())
        {
            String key = propertyKeys.next();
            if (key.trim().startsWith("replace"))
            {
                result.put(key, propertiesConfiguration.getString(key));
            }
        }
        return result;
    }

}
