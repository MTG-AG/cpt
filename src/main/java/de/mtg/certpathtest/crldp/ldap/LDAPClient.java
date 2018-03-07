
package de.mtg.certpathtest.crldp.ldap;

import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.regex.Pattern;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.Utils;

/**
 *
 * Objects of the class represent clients that connect to LDAP servers.
 *
 */
public class LDAPClient
{
    private static Logger logger = LoggerFactory.getLogger(LDAPClient.class);

    private final static String ATTRIBUTE_CRL = "certificateRevocationList";
    private final static String ATTRIBUTE_OBJECT_CLASS = "objectClass";
    private final static String ATTRIBUTE_PASSWORD = "userPassword";
    private final static String OBJECT_CLASS_TOP = "top";
    private final static String OBJECT_CLASS_CRLDP = "cRLDistributionPoint";
    private final static String OBJECT_CLASS_COUNTRY = "country";
    private final static String OBJECT_CLASS_DOMAIN = "domain";
    private final static String OBJECT_CLASS_ORGANIZATION = "organization";
    private final static String OBJECT_CLASS_ORGANIZATIONAL_UNIT = "organizationalUnit";
    private final static String FACTORY_NAME = "com.sun.jndi.ldap.LdapCtxFactory";

    /* The connection to the LDAP directory. */
    private DirContext ctx;

    private String rootDN;

    /**
     *
     * Constructs a newly allocated LDAPClient object. This represents an open connection to an LDAP server.
     *
     * @param host the hostname of the LDAP server this client is connecting.
     * @param port the port of the LDAP server this client is connecting.
     * @param rootDN the name of the root of the LDAP server this client is connecting.
     * @param user the user of the LDAP server that has write access.
     * @param password the password of this user.
     * @throws NamingException if the connection to the LDAP server is not possible.
     */
    public LDAPClient(String host, String port, String rootDN, String user, String password) throws NamingException
    {

        this.rootDN = rootDN;

        String url = "ldap://" + host + ":" + port + "/" + rootDN;

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAPClient.FACTORY_NAME);
        env.put(Context.PROVIDER_URL, url);
        env.put("java.naming.ldap.attributes.binary", LDAPClient.ATTRIBUTE_CRL);

        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, user);
        env.put(Context.SECURITY_CREDENTIALS, password);

        ctx = new InitialDirContext(env);
    }

    /**
     *
     * Writes this rawCRL on the path in LDAP identified by this dn.
     *
     * @param dn the LDAP distinguished name where this rawCRL is written.
     * @param rawCRL the certificate revocation list to write in the LDAP directory.
     * @throws NamingException if the CRL could not be written.
     */
    public void publishCRL(String dn, byte[] rawCRL) throws NamingException
    {

        if (dn.endsWith(rootDN))
        {
            dn = dn.substring(0, dn.length() - (rootDN.length() + 1));

            dn = dn.trim();

            if (dn.endsWith(","))
            {
                dn = dn.substring(0, dn.length() - 1);
            }
        }
        else
        {
            Utils.logError("Could not write CRL. LDAP root DN '" + rootDN + "' is incompatible with this DN '" + dn
                + "'.");
        }

        String[] rdns = dn.split(",");

        List<String> dnsAsList = Arrays.asList(rdns);

        Collections.reverse(dnsAsList);

        String[] tmpDN = new String[rdns.length];

        int counter = 0;
        String test = "";

        for (String rdn : dnsAsList)
        {
            if (counter != 0)
            {
                test = "," + test;
            }
            test = rdn + test;

            tmpDN[counter] = test.toString();
            counter += 1;
        }

        for (String entry : tmpDN)
        {
            try
            {
                ctx.lookup(entry);
            }
            catch (NameNotFoundException nnfe)
            {
                Attributes entryAttributes = getAttributes(entry);
                ctx.createSubcontext(entry, entryAttributes);
                ObjectCache.getInstance().addLDAPEntry(entry);
            }

        }

        ModificationItem[] modificationItems = new ModificationItem[1];
        modificationItems[0] =
            new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute(LDAPClient.ATTRIBUTE_CRL, rawCRL));
        ctx.modifyAttributes(dn, modificationItems);

    }

    /**
     *
     * Creates an LDIF entry for the entry with this dn in the LDAP directory. It appends the LDIP of this entry to the
     * previous ldifContent of the LDAP server.
     *
     * @param dn the distinguished name of the LDAP entry.
     * @param ldifContent the previous content of the LDAP server.
     * @param rootDN the DN of the root of the LDAP directory.
     * @throws NamingException if LDAP operation were not successful.
     */
    public void createLDIF(String dn, StringBuilder ldifContent, String rootDN) throws NamingException
    {
        Attributes attributes = ctx.getAttributes(dn);
        NamingEnumeration<? extends Attribute> attributesEnum = attributes.getAll();

        ldifContent.append("dn: ");
        ldifContent.append(dn);
        if (!StringUtils.isEmpty(dn))
        {
            ldifContent.append(",");
        }
        ldifContent.append(rootDN);

        ldifContent.append(System.getProperty("line.separator"));

        while (attributesEnum.hasMore())
        {
            BasicAttribute basicAttribute = (BasicAttribute) attributesEnum.next();

            NamingEnumeration<?> values = basicAttribute.getAll();

            while (values.hasMore())
            {

                if (basicAttribute.getID().startsWith("certificateRevocationList"))
                {
                    byte[] rawCRL = (byte[]) values.next();
                    ldifContent.append(basicAttribute.getID() + ":: " + new String(Base64.encode(rawCRL)));
                    ldifContent.append(System.getProperty("line.separator"));
                }
                else
                {

                    ldifContent.append(basicAttribute.getID() + ": " + (String) values.next());
                    ldifContent.append(System.getProperty("line.separator"));
                }
            }

        }

        ldifContent.append(System.getProperty("line.separator"));
    }

    /**
     *
     * Changes the default password of the user. Since Apache DS comes with a default password it is necessary to change
     * it as soon as the LDAP server goes online.
     *
     * @param host host the hostname of the LDAP server this client is connecting.
     * @param port port the port of the LDAP server this client is connecting.
     * @param user the user of the LDAP server that has write access.
     * @param oldPassword the old password (default) of the LDAP user that has write access.
     * @param newPassword the new password (chosen by the user) of the LDAP user that has write access.
     * @throws NamingException if password could not be changed.
     */
    public void changePassword(String host, String port, String user, String oldPassword, String newPassword)
                    throws NamingException
    {

        String url = "ldap://" + host + ":" + port + "/";

        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, LDAPClient.FACTORY_NAME);
        env.put(Context.PROVIDER_URL, url);
        env.put("java.naming.ldap.attributes.binary", LDAPClient.ATTRIBUTE_CRL);

        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, user);
        env.put(Context.SECURITY_CREDENTIALS, oldPassword);

        DirContext newContext = new InitialDirContext(env);

        ModificationItem[] modificationItems = new ModificationItem[1];
        modificationItems[0] = new ModificationItem(
                                                    DirContext.REPLACE_ATTRIBUTE,
                                                        new BasicAttribute(LDAPClient.ATTRIBUTE_PASSWORD, newPassword));
        newContext.modifyAttributes("uid=admin,ou=system", modificationItems);

        newContext.close();

    }

    private static Attributes getAttributes(String dn)
    {
        Attributes attibutes = new BasicAttributes();
        BasicAttribute objectClass = new BasicAttribute(ATTRIBUTE_OBJECT_CLASS);
        objectClass.add(OBJECT_CLASS_TOP);

        String tmpDN = dn.toLowerCase().replaceAll(Pattern.quote(" "), "");

        if (tmpDN.startsWith("cn="))
        {
            objectClass.add(LDAPClient.OBJECT_CLASS_CRLDP);
        }
        else if (tmpDN.startsWith("o="))
        {
            objectClass.add(LDAPClient.OBJECT_CLASS_ORGANIZATION);
        }
        else if (tmpDN.startsWith("ou="))
        {
            objectClass.add(LDAPClient.OBJECT_CLASS_ORGANIZATIONAL_UNIT);
        }
        else if (tmpDN.startsWith("c="))
        {
            objectClass.add(LDAPClient.OBJECT_CLASS_COUNTRY);
        }
        else if (tmpDN.startsWith("dc="))
        {
            objectClass.add(LDAPClient.OBJECT_CLASS_DOMAIN);
        }
        else
        {
            Utils.logError("Could not write CRL. Unsupported RDN in DN '" + dn
                + "'. Supported attributes are {cn, ou, o, c, dc}.");
        }

        attibutes.put(objectClass);

        return attibutes;
    }

    /**
     *
     * Closes the connection to the LDAP Directory.
     *
     * @throws NamingException if the connection of this client to the LDAP directory could not be closed.
     */
    public void close() throws NamingException
    {
        if (ctx != null)
        {
            ctx.close();
        }
    }

}
