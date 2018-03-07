/***********************************************************
 * media transfer AG
 *  Copyright (c) 2017
 *
 ***********************************************************/

package de.mtg.security.asn1.x509.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utilities.
 */
public class Util
{
    private static Provider BC = new BouncyCastleProvider();

    private Util()
    {
        // utility
    }

    /**
     * Builds an {@link X500Principal} from an {@link X500Name}.
     *
     * @param name
     * @return principal
     */
    public static X500Principal nameToPrincipal(X500Name name)
    {
        X500Principal pal = null;
        if (name != null)
        {
            try
            {
                pal = new X500Principal(name.getEncoded());
            }
            catch (IOException ex)
            {
                throw new IllegalStateException(ex);
            }
        }
        return pal;
    }

    /**
     * Builds an {@link X500Name} from an {@link X500Principal}.
     *
     * @param principal
     * @return name
     */
    public static X500Name principalToName(X500Principal principal)
    {
        X500Name name = null;

        if (principal != null)
        {
            name = X500Name.getInstance(principal.getEncoded());
        }

        return name;
    }

    /**
     * Builds {@link PublicKey} from {@link SubjectPublicKeyInfo}.
     *
     * @param subjectPublicKeyInfo
     * @return public key
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PublicKey buildPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
                    throws IOException, GeneralSecurityException
    {
        PublicKey publicKey = null;

        if (subjectPublicKeyInfo != null)
        {
            String algorithm = subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId();
            byte[] encoded = subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER);
            KeyFactory fact = KeyFactory.getInstance(algorithm, BC);
            publicKey = fact.generatePublic(new X509EncodedKeySpec(encoded));

            // may use BC directly
            // BC must be initialized for getPublicKey
            // publicKey = BouncyCastleProvider.getPublicKey(subjectPublicKeyInfo);
        }
        return publicKey;
    }

    /**
     *
     * Builds {@link PublicKey} from {@link SubjectPublicKeyInfo}.
     *
     * @param algorithm
     * @param encodedPublicKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey buildPublicKey(String algorithm, byte[] encodedPublicKey)
                    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PublicKey publicKey = null;

        if (encodedPublicKey != null)
        {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BC);
            publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));

        }
        return publicKey;
    }

    /**
     * Builds {@link SubjectPublicKeyInfo} from {@link PublicKey}.
     * <p>
     * The key must have format X.509 and support encoding.
     *
     * @param publicKey
     * @return key info
     * @throws IllegalArgumentException
     */
    public static SubjectPublicKeyInfo buildSubjectPublicKeyInfo(PublicKey publicKey)
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = null;

        if (publicKey != null)
        {
            byte[] encoded = publicKey.getEncoded();

            if (encoded != null && "X.509".equals(publicKey.getFormat()))
            {
                subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(encoded);
            }
            else
            {
                throw new IllegalArgumentException("illegal public key: " + publicKey);
            }
        }
        return subjectPublicKeyInfo;
    }

}
