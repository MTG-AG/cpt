
package de.mtg.certpathtest.pkiobjects.extensions;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.WrongPKIObjectException;

/**
 *
 * Instances of this class represent the AuthorityKeyIdentifier extension.
 *
 */
public class AuthorityKeyIdentifier extends XMLExtension
{

    private static Logger logger = LoggerFactory.getLogger(AuthorityKeyIdentifier.class);

    private byte[] publicKey;

    /**
     *
     * Constructs an AuthorityKeyIdentifier extension from its XML representation specified in this xmlExtension. This
     * representation is usually found in a PKI Object which is also specified in XML.
     *
     * @param xmlExtension the XML representation of this extension.
     * @param publicKey the public key of the CA of the certificate having this extension.
     * @throws WrongPKIObjectException if the XML representation specified in this xmlExtension is not conform to the
     *             XML specification (for example allowed values) for this extension.
     * @throws IOException if it was not possible to encode this extension.
     */
    public AuthorityKeyIdentifier(de.mtg.certpathtest.pkiobjects.Extension xmlExtension,
                                  byte[] publicKey) throws WrongPKIObjectException, IOException
    {
        super(xmlExtension);
        this.publicKey = publicKey;

        validate();

    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncodedFromPrettyRepresentation() throws NoSuchAlgorithmException, IOException
    {

        JcaX509ExtensionUtils util = new JcaX509ExtensionUtils();
        org.bouncycastle.asn1.x509.AuthorityKeyIdentifier aki =
            util.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(publicKey));

        byte[] rawValue = aki.getEncoded();

        return rawValue;

    }

    /**
     *
     * {@inheritDoc}
     *
     * The expected format is: empty.
     *
     */
    @Override
    public void validatePrettyRepresentation() throws WrongPKIObjectException
    {
        String value = getValue();

        if (value == null || value.isEmpty())
        {
            return;
        }

        String message = "The value of the Authority Key Identifier extension is not empty.";
        Utils.logError(message);
        throw new WrongPKIObjectException(message);

    }

}
