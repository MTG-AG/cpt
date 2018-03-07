
package de.mtg.certpathtest;

import java.nio.file.Path;

import de.mtg.certpathtest.pkiobjects.PKIObjects;

public class SetupObject
{
    private String filename;
    private PKIObjects pkiObjects;
    private Path file;

    public SetupObject(String filename, PKIObjects pkiObjects, Path file)
    {
        this.filename = filename;
        this.pkiObjects = pkiObjects;
        this.file = file;
    }

    public String getFilename()
    {
        return filename;
    }

    public PKIObjects getPkiObjects()
    {
        return pkiObjects;
    }

    public Path getPath()
    {
        return file;
    }
}
