
package de.mtg.certpathtest.crldp.ldap;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import java.io.File;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.Utils;

/**
 * A simple example exposing how to embed Apache Directory Server from the bleeding trunk into an application.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 *
 * Copied from Apache Directory Project and slightly adjusted for the purposes of CPT.
 */
public class EmbeddedADSVerTrunk
{
    /** The directory service */
    private DirectoryService service;

    /** The LDAP server */
    private LdapServer server;

    private String port;

    private static Logger logger = LoggerFactory.getLogger(EmbeddedADSVerTrunk.class);

    /**
     * initialize the schema manager and add the schema partition to directory service
     *
     * @throws Exception if the schema LDIF files are not found on the classpath
     */
    private void initSchemaPartition() throws Exception
    {
        final InstanceLayout instanceLayout = this.service.getInstanceLayout();

        final File schemaPartitionDirectory = new File(instanceLayout.getPartitionsDirectory(), "schema");

        // Extract the schema on disk (a brand new one) and load the registries
        if (schemaPartitionDirectory.exists())
        {
            logger.debug("LDPAP: schema partition already exists, skipping schema extraction.");
        }
        else
        {
            final SchemaLdifExtractor extractor =
                new DefaultSchemaLdifExtractor(instanceLayout.getPartitionsDirectory());
            extractor.extractOrCopy();
        }

        final SchemaLoader loader = new LdifSchemaLoader(schemaPartitionDirectory);
        final SchemaManager schemaManager = new DefaultSchemaManager(loader);

        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix Dn
        schemaManager.loadAllEnabled();

        final List<Throwable> errors = schemaManager.getErrors();

        if (errors.size() != 0)
        {
            throw new Exception(I18n.err(I18n.ERR_317, Exceptions.printErrors(errors)));
        }

        this.service.setSchemaManager(schemaManager);

        // Init the LdifPartition with schema
        // final LdifPartition schemaLdifPartition = new LdifPartition(schemaManager);
        final LdifPartition schemaLdifPartition = new LdifPartition(schemaManager, service.getDnFactory());
        schemaLdifPartition.setPartitionPath(schemaPartitionDirectory.toURI());

        // The schema partition
        final SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        schemaPartition.setWrappedPartition(schemaLdifPartition);
        this.service.setSchemaPartition(schemaPartition);
    }

    /**
     * Initialize the server. It creates the partition, adds the index, and injects the context entries for the created
     * partitions.
     *
     * @param workDir the directory to be used for storing the data
     * @throws Exception if there were some problems while initializing the system
     */
    private void initDirectoryService(final File workDir, String host, String port, String rootDN) throws Exception
    {
        // Initialize the LDAP service
        this.service = new DefaultDirectoryService();
        this.service.setInstanceLayout(new InstanceLayout(workDir));

        final CacheService cacheService = new CacheService();
        cacheService.initialize(this.service.getInstanceLayout());

        this.service.setCacheService(cacheService);

        // first load the schema
        this.initSchemaPartition();

        // then the system partition
        // this is a MANDATORY partition
        // DO NOT add this via addPartition() method, trunk code complains about
        // duplicate partition
        // while initializing
        // final JdbmPartition systemPartition = new JdbmPartition(this.service.getSchemaManager());
        final JdbmPartition systemPartition = new JdbmPartition(service.getSchemaManager(), service.getDnFactory());
        systemPartition.setId("system");
        systemPartition.setPartitionPath(new File(
                                                  this.service.getInstanceLayout().getPartitionsDirectory(),
                                                      systemPartition.getId()).toURI());
        systemPartition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));
        systemPartition.setSchemaManager(this.service.getSchemaManager());

        // mandatory to call this method to set the system partition
        // Note: this system partition might be removed from trunk
        this.service.setSystemPartition(systemPartition);

        // Disable the ChangeLog system
        this.service.getChangeLog().setEnabled(false);
        this.service.setDenormalizeOpAttrsEnabled(true);
        this.service.setAllowAnonymousAccess(true);

        // And start the service
        this.service.startup();

        Partition dataPartition = addPartition("data", rootDN, service.getDnFactory());

        if (!service.getAdminSession().exists(dataPartition.getSuffixDn()))
        {
            Dn root = new Dn(rootDN);
            Entry entryApache = service.newEntry(root);
            entryApache.add("objectClass", "top", "domain", "extensibleObject");
            String rootValue = rootDN.trim().toLowerCase();

            if (rootValue.startsWith("dc="))
            {
                rootValue = rootDN.substring(3);
            }
            else if (rootValue.startsWith("dc ="))
            {
                rootValue = rootDN.substring(4).trim();
            }
            else
            {
                Utils.logError("The root '"+rootDN+"' of the LDAP directory must be always a domain component.");
            }

            entryApache.add("dc", rootValue);
            service.getAdminSession().add(entryApache);
        }

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

        String configuredLDAPPassword =
            configurationProperties.getProperties().getString(ConfigurationProperties.LDAP_PASSWORD);

        if (StringUtils.isBlank(configuredLDAPPassword))
        {
            logger.info("You did not provide a password for the LDAP user. Leaving default.");
        }
        else
        {

            Modification changePassword = new DefaultModification(
                                                                  ModificationOperation.REPLACE_ATTRIBUTE,
                                                                      "userPassword",
                                                                      configuredLDAPPassword);

            Dn admin = new Dn("uid=admin,ou=system");
            try
            {

                service.getAdminSession().modify(admin, changePassword);
                logger.info("Successfully changed default password of the LDAP user.");
            }
            catch (Exception e)
            {
                Utils.logError("Could not change default password of the LDAP user.");
            }
        }

    }

    private Partition addPartition(String partitionId, String partitionDn, DnFactory dnFactory) throws Exception
    {
        // Create a new partition with the given partition id
        JdbmPartition partition = new JdbmPartition(service.getSchemaManager(), dnFactory);
        partition.setId(partitionId);
        partition.setPartitionPath(new File(service.getInstanceLayout().getPartitionsDirectory(), partitionId).toURI());
        partition.setSuffixDn(new Dn(partitionDn));
        service.addPartition(partition);

        return partition;
    }

    /**
     *
     * Creates a new instance of EmbeddedADS. It initializes the directory service.
     *
     * @param workDir the directory where the LDAP data are written.
     * @param host the host where the LDAP server is listening to.
     * @param port the port where the LDAP server is listening to.
     * @param rootDN the DN of the root of the LDAP server.
     *
     * @throws Exception if something went wrong.
     */
    public EmbeddedADSVerTrunk(final File workDir, String host, String port, String rootDN) throws Exception
    {
        this.port = port;
        if (!workDir.exists())
        {
            workDir.mkdirs();
            this.initDirectoryService(workDir, host, port, rootDN);
            this.service.shutdown();
        }

        this.initDirectoryService(workDir, host, port, rootDN);
    }

    /**
     * starts the LdapServer
     *
     * @throws Exception if an exception occurs.
     */
    public void startServer() throws Exception
    {
        this.server = new LdapServer();
        final int serverPort = Integer.parseInt(this.port);
        this.server.setTransports(new TcpTransport(serverPort));
        this.server.setDirectoryService(this.service);

        this.server.start();
    }

    /**
     * Main class.
     *
     * @param args Not used.
     */
    public static void main(final String[] args)
    {
        try
        {

            // this is needed to avoid DEBUG messages from the apache DS library
            ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger("org.apache.directory")).setLevel(ch.qos.logback.classic.Level.WARN);
            ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger("org.apache.mina")).setLevel(ch.qos.logback.classic.Level.WARN);
            ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger("net.sf.ehcache")).setLevel(ch.qos.logback.classic.Level.WARN);

            final File workDir = new File("ldapData");

            // Create the server
            final EmbeddedADSVerTrunk ads =
                new EmbeddedADSVerTrunk(workDir, "certpath_test_host", "10389", "dc=ldap-root");

            // optionally we can start a server too
            ads.startServer();
        }
        catch (final Exception e)
        {
            // Ok, we have something wrong going on ...
            e.printStackTrace();
        }
    }
}