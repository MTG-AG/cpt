
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.ValueType;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.RegExpValidator;
import de.mtg.security.asn1.x509.common.SimpleExtension;

/**
 *
 * Objects of this class and its subclasses represent certificate or CRLs extensions. The extensions are specified in
 * XML and using this class and its subclasses it is possible to validate that it is possible to build an extension to
 * use in a certificate or CRL. An example of such an extension is:
 *
 * <pre>
 * <Extension oid="2.5.29.19" critical="true" name="Basic Constraints" type="pretty">true,0</Extension>
 * </pre>
 *
 */
public abstract class XMLExtension
{
    private static Logger logger = LoggerFactory.getLogger(XMLExtension.class);

    private boolean isCritical;
    private ValueType type;
    private String value;
    private String oid;

    /**
     *
     * Constructs a newly allocated XMLExtension object.
     *
     * @param xmlExtension the extension specified in XML.
     * @throws WrongPKIObjectException if mandatory attributes are missing or contain wrong values.
     */
    public XMLExtension(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException
    {

        String oid = xmlExtension.getOid();
        String critical = xmlExtension.getCritical();
        String type = xmlExtension.getType();
        String value = xmlExtension.getValue();

        // 01. checking presence of values

        if (oid == null || oid.isEmpty())
        {
            String message = "The OID for this extension is not provided.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        if (critical == null || critical.isEmpty())
        {
            String message = "The OID for this extension is not provided.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        if (type == null || type.isEmpty())
        {
            String message = "The type for this extension is not provided.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        // 02. checking correctness of values

        oid = oid.trim();

        RegExpValidator regExpValidator = new RegExpValidator("(\\d+\\.{1})*\\d+");
        boolean isOID = regExpValidator.validate(oid);

        if (!isOID)
        {
            String message = "The provided value for the OID of this extension '" + oid + "' is not a valid OID.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        critical = critical.trim();

        if (!("true".equalsIgnoreCase(critical) || "false".equalsIgnoreCase(critical)))
        {
            String message = "The provided value for the critical flag of this extension '" + critical
                + "' is not valid. Allowed values: true or false.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        type = type.trim();
        this.type = ValueType.valueOf(type.toUpperCase());

        if (!(ValueType.RAW == this.type || ValueType.PRETTY == this.type))
        {
            String message = "The provided value for the type of this extension '" + type
                + "' is not a valid type. Allowed values: raw or pretty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        if (ValueType.RAW == ValueType.valueOf(type.toUpperCase()))
        {
            if (value == null || value.isEmpty())
            {
                String message = "The value for this extension is not provided althought it's type is raw.";
                Utils.logError(message);
                throw new WrongPKIObjectException(message);
            }
        }

        // 03. assigning values

        this.oid = oid;
        this.isCritical = Boolean.parseBoolean(critical);
        this.value = value;

    }

    /**
     *
     * Checks whether the pretty representation of this extension is correct and a corresponding extension for use in a
     * certificate or CRL can be created. If the representation is wrong this extension cannot be created.
     *
     * @throws WrongPKIObjectException if this extension has a wrong pretty representation.
     */
    public abstract void validatePrettyRepresentation() throws WrongPKIObjectException;

    /**
     * Returns the encoded value directly from the pretty representation in XML. Parses the pretty description of the
     * XML data, creates a correct extension object and returns the encoded value. It returns the extnValue of the
     * extension (see Section 4.1 of RFC 5280).
     *
     * <pre>
     * Extension  ::=  SEQUENCE  {
     *  extnID      OBJECT IDENTIFIER,
     *  critical    BOOLEAN DEFAULT FALSE,
     *  extnValue   OCTET STRING
     *              -- contains the DER encoding of an ASN.1 value
     *              -- corresponding to the extension type identified
     *              -- corresponding to the extension type identified
     * }
     * </pre>
     *
     * @param xmlValue the pretty value of this extension specified in the XML data.
     * @return the encoded value of this extension, that is the extnValue of the extension (RFC 5280)
     * @throws Exception if this extension cannot be encoded from the XML representation.
     */
    public abstract byte[] getEncodedFromPrettyRepresentation() throws Exception;

    /**
     *
     * Returns the criticality flag of this extension.
     *
     * @return true if this extension is marked as critical, false otherwise.
     */
    public boolean isCritical()
    {
        return this.isCritical;
    }

    /**
     *
     * Returns the value of this extension. This can be in pretty human readable format or base64 encoding of a DER
     * encoded value.
     *
     * @return the value of this extension specified in the XML representation.
     */
    public String getValue()
    {
        return this.value;
    }

    /**
     *
     * Returns the type of this extension. It can be <code>raw</code> or <code>pretty</code>.
     *
     * @return <code>raw</code> if it is a representation in base64 or <code>pretty</code> if is in a human readable
     *         format.
     */
    public ValueType getType()
    {
        return this.type;
    }

    /**
     *
     * Returns the OID of this extension.
     *
     * @return the OID of this extension.
     */
    public ASN1ObjectIdentifier getOID()
    {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(this.oid);
        return oid;
    }

    /**
     *
     * Returns the OID of this extension as a String.
     *
     * @return the OID of this extension as a String.
     */
    public String getOIDAsString()
    {
        ASN1ObjectIdentifier oid = getOID();

        if (oid != null)
        {
            String oidString = oid.getId();
            return oidString;
        }
        else
        {
            return null;
        }
    }

    /**
     *
     * Checks whether the value specified in the XML representation of this extension is correct and can lead to a
     * encoded extension that can be used further in certificate and CRLs.
     *
     * @return true if this extension contains a correct value, false otherwise.
     * @throws WrongPKIObjectException if the value of this extension is wrong and therefore an extension cannot be
     *             created.
     */
    public boolean validate() throws WrongPKIObjectException
    {
        if (ValueType.RAW.equals(type))
        {
            try
            {
                Base64.decode(value.getBytes());
                return true;
            }
            catch (Exception e)
            {
                Utils.logError("Could not decode the base64 encoded value of this extension.");
                return false;
            }

        }
        else
        {
            validatePrettyRepresentation();
            return true;
        }
    }

    /**
     *
     * Returns the extnValue of the extension (see Section 4.1 of RFC 5280).
     *
     * <pre>
     * Extension  ::=  SEQUENCE  {
     *  extnID      OBJECT IDENTIFIER,
     *  critical    BOOLEAN DEFAULT FALSE,
     *  extnValue   OCTET STRING
     *              -- contains the DER encoding of an ASN.1 value
     *              -- corresponding to the extension type identified
     *              -- corresponding to the extension type identified
     * }
     * </pre>
     *
     * @return the encoded value of this extension, that is the extnValue of the extension (RFC 5280).
     * @throws Exception if this extension cannot be encoded from the XML representation.
     */
    public byte[] getEncoded() throws Exception
    {

        if (ValueType.RAW.equals(type))
        {
            byte[] decoded = Base64.decode(value.getBytes());
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
            DEROctetString octetString = (DEROctetString) asn1InputStream.readObject();
            asn1InputStream.close();
            bais.close();
            return octetString.getOctets();
        }
        else
        {
            return getEncodedFromPrettyRepresentation();
        }
    }

    /**
     *
     * Returns the Extension element of the extension (see Section 4.1 of RFC 5280). This can be placed directly in the
     * certificate or CRL.
     *
     * <pre>
     * Extension  ::=  SEQUENCE  {
     *  extnID      OBJECT IDENTIFIER,
     *  critical    BOOLEAN DEFAULT FALSE,
     *  extnValue   OCTET STRING
     *              -- contains the DER encoding of an ASN.1 value
     *              -- corresponding to the extension type identified
     *              -- corresponding to the extension type identified
     * }
     * </pre>
     *
     * @return the extension to place it directly in the certificate or CRL.
     * @throws Exception if this extension cannot be created from the XML representation.
     */
    public SimpleExtension getSimpleExtension() throws Exception
    {
        SimpleExtension simpleExtension = new SimpleExtension();

        if (isCritical())
        {
            simpleExtension.setCritical(true);
        }

        simpleExtension.setExtnId(getOID());
        simpleExtension.setExtnValueOctets(getEncoded());
        return simpleExtension;
    }

}
