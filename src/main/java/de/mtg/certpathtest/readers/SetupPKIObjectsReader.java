
package de.mtg.certpathtest.readers;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.SetupObject;
import de.mtg.certpathtest.Utils;
import de.mtg.certpathtest.pkiobjects.PKIObjects;

public class SetupPKIObjectsReader extends SimpleFileVisitor<Path>
{

    private static Logger logger = LoggerFactory.getLogger(SetupPKIObjectsReader.class);

    private PathMatcher pathMatcher;
    private ArrayList<SetupObject> setupObjects = new ArrayList<SetupObject>();

    public SetupPKIObjectsReader()
    {
        pathMatcher = FileSystems.getDefault().getPathMatcher("glob:*.{xml}");
    }

    public ArrayList<SetupObject> getPKIObjects()
    {
        return setupObjects;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult visitFile(Path file, BasicFileAttributes basicFileAttributes) throws IOException
    {

        JAXBContext jaxb = null;
        try
        {
            jaxb = JAXBContext.newInstance(PKIObjects.class);
            Unmarshaller unmarshaller = jaxb.createUnmarshaller();
            PKIObjects setupFile = (PKIObjects) unmarshaller.unmarshal(file.toFile());
            SetupObject setupObject = new SetupObject(file.toFile().getName(), setupFile, file);
            setupObjects.add(setupObject);
        }
        catch (JAXBException e)
        {
            Utils.logError("Could not parse PKI Objects setup file. "+ e);
            logger.debug("", e);
            throw new IOException(e);
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
        Utils.logError("Could not read file '"+file.toString()+"'.");
        logger.error("", ioe);
        return FileVisitResult.CONTINUE;
    }

}