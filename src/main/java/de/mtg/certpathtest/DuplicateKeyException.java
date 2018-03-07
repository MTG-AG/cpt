
package de.mtg.certpathtest;

/**
 * Instances of this class express error in the XML structure of PKI objects.
 *
 */
public class DuplicateKeyException extends Exception
{

    /**
     *
     * Constructs a newly allocated DuplicateKeyException object.
     *
     */
    public DuplicateKeyException()
    {
        super();
    }

    /**
     *
     * Constructs a newly allocated DuplicateKeyException object.
     *
     * @param message the message associated with this exception.
     */
    public DuplicateKeyException(String message)
    {
        super(message);
    }

    /**
     *
     * Constructs a newly allocated DuplicateKeyException object.
     *
     * @param throwable the throwable.
     */
    public DuplicateKeyException(Throwable throwable)
    {
        super(throwable);
    }

    /**
     *
     * Constructs a newly allocated DuplicateKeyException object.
     *
     * @param message the message associated with this exception.
     * @param throwable the throwable.
     */
    public DuplicateKeyException(String message, Throwable throwable)
    {
        super(message, throwable);
    }

}
