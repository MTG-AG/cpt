
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;
import de.mtg.certpathtest.validators.RegExpValidator;

/**
 *
 * Instances of this class represent the PolicyMappings extension.
 *
 */
public class PolicyMappings extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(PolicyMappings.class);

    /**
     *
     * Constructs a PolicyMappings extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public PolicyMappings(de.mtg.certpathtest.pkiobjects.Extension xmlExtension) throws WrongPKIObjectException,
                                                                                 IOException
    {
        super(xmlExtension);
        validate();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedFromPrettyRepresentation() throws IOException
    {
        String value = getValue();

        StringTokenizer tokenizer = new StringTokenizer(value, "|");

        int numberOfMappings = tokenizer.countTokens();
        int counter = 0;
        CertPolicyId[] issuerDomainPolicies = new CertPolicyId[numberOfMappings];
        CertPolicyId[] subjectDomainPolicies = new CertPolicyId[numberOfMappings];

        while (tokenizer.hasMoreTokens())
        {
            String policyMapping = tokenizer.nextToken();

            StringTokenizer oneMappingTokenizer = new StringTokenizer(policyMapping.trim(), ",");

            CertPolicyId issuerDomainPolicy = CertPolicyId.getInstance(new ASN1ObjectIdentifier(
                                                                                                oneMappingTokenizer.nextToken()
                                                                                                                   .trim()));
            CertPolicyId subjectDomainPolicy = CertPolicyId.getInstance(new ASN1ObjectIdentifier(
                                                                                                 oneMappingTokenizer.nextToken()
                                                                                                                    .trim()));
            issuerDomainPolicies[counter] = issuerDomainPolicy;
            subjectDomainPolicies[counter] = subjectDomainPolicy;
            counter += 1;

        }

        org.bouncycastle.asn1.x509.PolicyMappings policyMappings =
            new org.bouncycastle.asn1.x509.PolicyMappings(issuerDomainPolicies, subjectDomainPolicies);

        return policyMappings.getEncoded();

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: <code>1.2,1.2.3|1.3.4,1.5.6</code>.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {

        String value = getValue();

        if (value == null || value.isEmpty())
        {
            String message = "The value of the Policy Mappings extension should not be empty.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

        RegExpValidator regexpValidator = new RegExpValidator(
                                                              "((\\d+\\.{1})*\\d+),\\s?((\\d+\\.{1})*\\d+)(\\|((\\d+\\.{1})*\\d+),\\s?((\\d+\\.{1})*\\d+))*");

        if (!regexpValidator.validate(value))
        {
            String message = "Wrong value '" + value + "' for the Policy Mappings extension.";
            Utils.logError(message);
            throw new WrongPKIObjectException(message);
        }

    }

}
