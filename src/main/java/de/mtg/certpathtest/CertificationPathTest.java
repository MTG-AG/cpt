
package de.mtg.certpathtest;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.stream.Stream;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.convert.DefaultListDelimiterHandler;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.FileAppender;
import de.mtg.certpathtest.crldp.ServerMode;
import de.mtg.certpathtest.pkiobjects.PKIObjects;
import de.mtg.certpathtest.readers.ExtractDataReader;
import de.mtg.certpathtest.readers.SetupPKIObjectsReader;
import de.mtg.certpathtest.testcase.handlers.CreateCertificateHandler;
import de.mtg.certpathtest.testcase.handlers.OutputHandler;
import de.mtg.certpathtest.testcase.handlers.PathExportHandler;
import de.mtg.tr03124.TestCase;

/**
 *
 * This class is used as the entry point for starting a the tool for producing certificates and CRLs to be used in test
 * procedures.
 *
 */
public class CertificationPathTest
{

    private static Logger logger;

    private static final String COMMAND_HELP = "java -cp \"lib/*\" de.mtg.certpathtest.CertificationPathTest";
    private static final String DEFAULT_PROPERTIES_FILENAME = "cpt.ini";
    private static final String LOG_FILENAME_PROPERTY = "log.filename";
    private static final String LOG_LEVEL_PROPERTY = "log.level";
    private static final String LOG_PATTERN_PROPERTY = "log.pattern";
    private static final String LOG_CONSOLE_PROPERTY = "log.console";

    private static final String LOG_FILENAME_PROPERTY_DEFAULT = "cpt.log";
    private static final String LOG_LEVEL_PROPERTY_DEFAULT = "INFO";
    private static final String LOG_PATTERN_PROPERTY_DEFAULT =
        "%date %level [%thread] %logger{10} [%file:%line] %msg%n";
    private static final boolean LOG_CONSOLE_PROPERTY_DEFAULT = false;

    /**
     *
     * Runs the program for producing certificates and CRLs to be used in test procedures.
     *
     * @param args the command line arguments for calling the program.
     * @throws IOException if files cannot be read.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
                    InvalidAlgorithmParameterException
    {

        Option helpOption = new Option("h", "help", false, "print this message");

        Option configurationFileOption = new Option("c", true, "configuration file");
        configurationFileOption.setArgName("configurationFile");

        Option directoryWithXmlTestFiles = new Option("d", true, "directory containing test cases");
        directoryWithXmlTestFiles.setArgName("directory");

        Option outputDirectory = new Option("o", true, "the directory to write the output");
        outputDirectory.setArgName("output directory");

        Option publicKeyOption = new Option("p", true, "the specification of the public key");
        publicKeyOption.setArgName("public key spec");

        Option serverModeOption = new Option("s", false, "runs the tool as a HTTP/LDAP server");
        serverModeOption.setArgName("server mode");

        Options options = new Options();

        options.addOption(helpOption);
        options.addOption(configurationFileOption);
        options.addOption(directoryWithXmlTestFiles);
        options.addOption(outputDirectory);
        options.addOption(publicKeyOption);
        options.addOption(serverModeOption);

        HelpFormatter helpFormatter = new HelpFormatter();

        if (args == null || args.length == 0)
        {
            helpFormatter.printHelp(CertificationPathTest.COMMAND_HELP, options);
            System.out.println("Program is exiting.");
            System.exit(0);
        }

        CommandLineParser cliPraser = new DefaultParser();
        CommandLine cli = null;
        try
        {
            cli = cliPraser.parse(options, args);
        }
        catch (ParseException pe)
        {
            System.out.println(pe.getMessage());
            helpFormatter.printHelp(CertificationPathTest.COMMAND_HELP, options);
            System.out.println("Program is exiting.");
            System.exit(0);
        }

        Security.addProvider(new BouncyCastleProvider());

        if (cli.hasOption("p"))
        {
            printPublicKeyValue(cli.getOptionValue("p"));
            System.exit(0);
        }

        // this is needed to avoid a message from the bean utils library
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.NoOpLog");

        // this is needed to avoid DEBUG messages from the jetty library
        ((Logger) LoggerFactory.getLogger("org.eclipse.jetty")).setLevel(Level.INFO);

        // this is needed to avoid DEBUG messages from the apache DS library
        ((Logger) LoggerFactory.getLogger("org.apache.directory")).setLevel(Level.WARN);
        ((Logger) LoggerFactory.getLogger("org.apache.mina")).setLevel(Level.WARN);
        ((Logger) LoggerFactory.getLogger("net.sf.ehcache")).setLevel(Level.WARN);

        String propertiesFilename = DEFAULT_PROPERTIES_FILENAME;

        if (cli.hasOption("c"))
        {
            propertiesFilename = cli.getOptionValue("c");
        }

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();
        try
        {
            configurationProperties.init(propertiesFilename);
        }
        catch (Exception e)
        {
            System.out.println("Could not parse properties file '" + propertiesFilename
                + "'. Please correct this file and restart.");
            System.out.println("Program is exiting.");
            System.exit(0);
        }

        initLogging(configurationProperties.getProperties());
        logger.info("Logging started.");
        logger.info("Test tool is starting.");

        boolean useHTTP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.HTTP_USE);
        boolean useLDAP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.LDAP_USE);

        if (cli.hasOption("s"))
        {

            logger.info("Test tool runs as a server. No certificates/CRLs are created.");

            if (!(useHTTP || useLDAP))
            {
                String message =
                    "Server mode is chosen (option -s in the command line) but it is configured not to use HTTP or LDAP.";
                Utils.exitProgramm(message);
            }
            else
            {
                ServerMode serverMode = new ServerMode();
                serverMode.activate(false);
            }

        }
        else
        {

            String outputDirectoryName = null;
            String testCasesDirectoryName = null;

            if (cli.hasOption("o"))
            {
                outputDirectoryName = cli.getOptionValue("o");

                File dir = new File(outputDirectoryName);
                if (dir.exists())
                {
                    if (!dir.isDirectory())
                    {
                        Utils.exitProgramm("Location under '{" + outputDirectoryName
                            + "}' is not a directory. It must be a directory.");
                    }

                    if (!dir.canWrite())
                    {
                        Utils.exitProgramm("Cannot write in directory '{" + outputDirectoryName + "}'.");
                    }
                }

                configurationProperties.addSimpleProperty(ConfigurationProperties.OUTPUT_DIRECTORY_PROPERTY,
                                                          outputDirectoryName);
            }
            else
            {
                Utils.exitProgramm("No output directory is specified. Use the -o option.");
            }

            if (cli.hasOption("d"))
            {
                testCasesDirectoryName = cli.getOptionValue("d");

                Files.walkFileTree(Paths.get(testCasesDirectoryName), new ExtractDataReader());
            }
            else
            {
                Utils.exitProgramm("A test case directory has not been specified. Use the -d option.");
            }

            logger.trace(ObjectCache.getInstance().toString());

            try
            {

                Runner ch = new Runner();
                ch.run();
            }
            catch (Exception e)
            {
                Utils.logError("Error during execution. " + e);
                logger.error("", e);
            }

            String archivesDirName = "archives";

            try
            {

                Path outputPath = Paths.get(outputDirectoryName);

                File dir = new File(archivesDirName);
                if (dir.exists())
                {
                    if (!dir.isDirectory())
                    {
                        Utils.logError("Archive directory '" + outputDirectoryName + "' is not a directory.");
                    }

                    if (!dir.canWrite())
                    {
                        Utils.logError("Cannot write in archive directory '" + outputDirectoryName + "'.");
                    }
                }
                else
                {
                    dir.mkdirs();
                }

                SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
                String timestamp = sdf.format(new Date());

                ObjectCache.getInstance().setArchiveTimestamp(timestamp);

                String certDataFilename =
                    archivesDirName + System.getProperty("file.separator") + timestamp + "-CERT.zip";
                String confDataFilename =
                    archivesDirName + System.getProperty("file.separator") + timestamp + "-CONF.zip";

                Utils.writeZip(certDataFilename, outputPath);

                String pkiObjectsLocation = ConfigurationProperties.getInstance().getProperties()
                                                                   .getString(ConfigurationProperties.PKI_OBJECTS_INPUT_DIRECTORY,
                                                                              "pkiObjects");

                Path pkiObjectsPath = Paths.get(pkiObjectsLocation);
                Path configFile = Paths.get(propertiesFilename);
                Utils.writeZip(confDataFilename, pkiObjectsPath);
                // Files.copy(configFile, testCasesPath);

                String filename = archivesDirName + System.getProperty("file.separator") + timestamp + "-cpt.ini";
                Files.copy(configFile, Paths.get(filename));

            }
            catch (IOException ioe)
            {
                Utils.logError("Could not archive certificate and/or configuration data. " + ioe);
                logger.debug(" ", ioe);
            }

            // handle setup certificates(for example for OpenVPN). These are not part of the testing procedure.

            String setupPkiObjectsPath =
                ConfigurationProperties.getInstance().getProperties()
                                       .getString(ConfigurationProperties.SETUP_PKI_OBJECTS_INPUT_DIRECTORY, "setup");

            SetupPKIObjectsReader setupPkiObjectsReader = new SetupPKIObjectsReader();

            Files.walkFileTree(Paths.get(setupPkiObjectsPath), setupPkiObjectsReader);
            ArrayList<SetupObject> setupObjects = setupPkiObjectsReader.getPKIObjects();

            String setupOutputDir = ConfigurationProperties.getInstance().getProperties().getString(
                                                                                                    ConfigurationProperties.SETUP_OUTPUT_DIRECTORY_PROPERTY,
                                                                                                    "setupOutput");;

            for (SetupObject setupObject : setupObjects)
            {

                try
                {
                    Random random = new Random();
                    String id = Integer.toHexString(random.nextInt(Integer.MAX_VALUE));

                    TestCase dummyTestCase = new TestCase();
                    dummyTestCase.setId(id);

                    ObjectCache objectCache = ObjectCache.getInstance();
                    objectCache.addTestCase(dummyTestCase, id);
                    PKIObjects pkiObjectsToWorkOn = Utils.applyReplacementsOnPKIObjects(setupObject.getPkiObjects());
                    objectCache.addPKIobjectsToTestCase(id, pkiObjectsToWorkOn);
                    ExtractDataReader.assignObjectsToTestCase(dummyTestCase, setupObject.getPkiObjects());

                    CreateCertificateHandler createCertificateHandler = new CreateCertificateHandler(dummyTestCase);
                    createCertificateHandler.execute();
                    OutputHandler outputHandler = new OutputHandler(dummyTestCase);
                    outputHandler.execute();
                    PathExportHandler pathExportHandler = new PathExportHandler(dummyTestCase);
                    pathExportHandler.execute();

                    Path outputDir = Paths.get(outputDirectoryName, id);

                    // remove .xml and use PKI Object name as output directory.
                    String name = setupObject.getFilename().substring(0, setupObject.getFilename().length() - 4);

                    if (!Files.exists(Paths.get(setupOutputDir, name)))
                    {
                        Files.createDirectories(Paths.get(setupOutputDir, name));
                    }

                    Stream<Path> files = Files.list(outputDir);

                    Iterator<Path> filesIterator = files.iterator();

                    while (filesIterator.hasNext())
                    {
                        Path srcFile = filesIterator.next();

                        // paths
                        if (Files.isDirectory(srcFile))
                        {
                            Stream<Path> pathFiles = Files.list(srcFile);
                            Iterator<Path> pathFilesIterator = pathFiles.iterator();
                            while (pathFilesIterator.hasNext())
                            {
                                Path pathsSrcFile = pathFilesIterator.next();
                                Files.copy(pathsSrcFile,
                                           Paths.get(setupOutputDir, name, pathsSrcFile.toFile().getName()),
                                           REPLACE_EXISTING);
                                Files.delete(pathsSrcFile);
                            }
                            Files.delete(srcFile);
                            pathFiles.close();
                        }
                        else
                        {
                            Files.copy(srcFile, Paths.get(setupOutputDir, name, srcFile.toFile().getName()),
                                       REPLACE_EXISTING);
                            Files.delete(srcFile);
                        }
                    }
                    files.close();
                    Files.delete(outputDir);
                }
                catch (Exception e)
                {
                    Utils.logError("" + e);
                    logger.error("", e);
                }

                Files.copy(setupObject.getPath(), Paths.get(setupOutputDir, setupObject.getFilename()),
                           REPLACE_EXISTING);
            }

            String setupDataFilename = archivesDirName + System.getProperty("file.separator")
                + ObjectCache.getInstance().getArchiveTimestamp() + "-SETUP.zip";

            Utils.writeZip(setupDataFilename, Paths.get(setupOutputDir));

            // finished setup processing

            // Show errors

            List<String> errors = ObjectCache.getInstance().getErrors();

            if (!errors.isEmpty())
            {
                logger.error("There was at least one error during execution of this program. Please consult the log file, correct the errors and restart the program. ");
            }

            for (String description : errors)
            {
                logger.error(description);
            }

            if (useHTTP || useLDAP)
            {
                ServerMode serverMode = new ServerMode();
                serverMode.activate(true);
            }
        }

        logger.info("Program finished.");

    }

    private static PropertiesConfiguration readProperties(String propertiesFilename)
                    throws IOException, org.apache.commons.configuration2.ex.ConfigurationException
    {

        checkFile(propertiesFilename, "Properties");

        FileBasedConfigurationBuilder<PropertiesConfiguration> builder =
            new FileBasedConfigurationBuilder<PropertiesConfiguration>(PropertiesConfiguration.class).configure(new Parameters().properties()
                                                                                                                                .setFileName(propertiesFilename)
                                                                                                                                .setThrowExceptionOnMissing(true)
                                                                                                                                .setListDelimiterHandler(new DefaultListDelimiterHandler(';'))
                                                                                                                                .setIncludesAllowed(false));
        PropertiesConfiguration propertiesConfiguration = builder.getConfiguration();

        return propertiesConfiguration;
    }

    private static File checkFile(String filename, String filetype) throws IOException
    {
        File file = new File(filename);
        if (!file.exists())
        {
            Utils.exitProgramm(filetype + " file '{" + filename + "}' does not exist.");
        }

        if (file.isDirectory())
        {
            Utils.exitProgramm(filetype + " file '{" + filename + "}' is a directory. It must be a file.");
        }

        if (!file.canRead())
        {
            Utils.exitProgramm(filetype + " file '{" + filename + "}' is not readable.");
        }
        return file;
    }

    private static void initLogging(PropertiesConfiguration properties)
    {

        String logfileName = properties.getString(CertificationPathTest.LOG_FILENAME_PROPERTY,
                                                  CertificationPathTest.LOG_FILENAME_PROPERTY_DEFAULT);
        String logLevel = properties.getString(CertificationPathTest.LOG_LEVEL_PROPERTY,
                                               CertificationPathTest.LOG_LEVEL_PROPERTY_DEFAULT);
        String pattern = properties.getString(CertificationPathTest.LOG_PATTERN_PROPERTY,
                                              CertificationPathTest.LOG_PATTERN_PROPERTY_DEFAULT);
        boolean logToConsole = properties.getBoolean(CertificationPathTest.LOG_CONSOLE_PROPERTY,
                                                     CertificationPathTest.LOG_CONSOLE_PROPERTY_DEFAULT);

        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

        PatternLayoutEncoder filePatternLayoutEncoder = new PatternLayoutEncoder();
        filePatternLayoutEncoder.setContext(loggerContext);
        filePatternLayoutEncoder.setPattern(pattern);
        filePatternLayoutEncoder.start();

        FileAppender<ILoggingEvent> logFileAppender = new FileAppender<ILoggingEvent>();
        logFileAppender.setContext(loggerContext);
        logFileAppender.setEncoder(filePatternLayoutEncoder);
        logFileAppender.setAppend(true);
        logFileAppender.setFile(logfileName);
        logFileAppender.start();

        logger = loggerContext.getLogger("de");
        logger.setAdditive(false);
        logger.setLevel(Level.valueOf(logLevel));
        logger.addAppender(logFileAppender);

        if (logToConsole)
        {
            PatternLayoutEncoder consolePatternLayoutEncoder = new PatternLayoutEncoder();
            consolePatternLayoutEncoder.setContext(loggerContext);
            consolePatternLayoutEncoder.setPattern(pattern);
            consolePatternLayoutEncoder.start();
            ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<ILoggingEvent>();
            consoleAppender.setContext(loggerContext);
            consoleAppender.setEncoder(consolePatternLayoutEncoder);
            consoleAppender.start();
            logger.addAppender(consoleAppender);
        }

    }

    private static void printPublicKeyValue(String input)
                    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair kp = null;

        StringTokenizer tokenizer = new StringTokenizer(input, ",");

        // holds the algorithm
        String algorithm = tokenizer.nextToken().trim();
        String parameter = tokenizer.nextToken().trim();

        if (algorithm.startsWith("RSA"))
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(Integer.parseInt(parameter), new SecureRandom());
            kp = kpg.generateKeyPair();
        }
        else if (algorithm.startsWith("ECDSA"))
        {
            ECParameterSpec ecps = ECNamedCurveTable.getParameterSpec(parameter);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecps);
            kp = kpg.generateKeyPair();
        }
        else if (algorithm.startsWith("ECDH"))
        {
            ECParameterSpec ecps = ECNamedCurveTable.getParameterSpec(parameter);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
            kpg.initialize(ecps);
            kp = kpg.generateKeyPair();
        }
        else
        {
            Utils.logError("Unknown algorithm/parameter '" + input + "'. Cannot create key pair.");
        }

        PrivateKey privateKey = kp.getPrivate();
        java.security.PublicKey publicKey = kp.getPublic();

        String value = new String(Base64.encode(publicKey.getEncoded())) + "|"
            + new String(Base64.encode(privateKey.getEncoded()));

    }

}
