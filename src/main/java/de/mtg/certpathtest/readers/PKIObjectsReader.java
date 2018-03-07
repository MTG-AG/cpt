
package de.mtg.certpathtest.readers;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.PKIObjects;

public class PKIObjectsReader extends SimpleFileVisitor<Path>
{

    private static Logger logger = LoggerFactory.getLogger(PKIObjectsReader.class);

    private PathMatcher pathMatcher;
    private PKIObjects pkiObjects;

    public PKIObjectsReader(String filename)
    {
        pathMatcher = FileSystems.getDefault().getPathMatcher("glob:" + filename);
    }

    public PKIObjects getPKIObjects()
    {
        return pkiObjects;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult visitFile(Path file, BasicFileAttributes basicFileAttributes) throws IOException
    {
        Path name = file.getFileName();

        if (name != null && pathMatcher.matches(name))
        {
            JAXBContext jaxb = null;
            try
            {
                jaxb = JAXBContext.newInstance(PKIObjects.class);
                Unmarshaller unmarshaller = jaxb.createUnmarshaller();
                this.pkiObjects = (PKIObjects) unmarshaller.unmarshal(file.toFile());
            }
            catch (JAXBException e)
            {
                Utils.logError("Could not parse PKI Objects file. " + e);
                logger.debug("", e);
                throw new IOException(e);
            }
        }
        return FileVisitResult.CONTINUE;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes basicFileAttributes)
    {
        return FileVisitResult.CONTINUE;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult postVisitDirectory(Path dir, IOException ioe)
    {
        return FileVisitResult.CONTINUE;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult visitFileFailed(Path file, IOException ioe)
    {
        Utils.logError("Could not read file '" + file.toString() + "'.");
        return FileVisitResult.CONTINUE;
    }

}