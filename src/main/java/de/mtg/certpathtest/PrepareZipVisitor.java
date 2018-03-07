package de.mtg.certpathtest;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.regex.Pattern;

public class PrepareZipVisitor extends SimpleFileVisitor<Path>
{

    private ArrayList<String> fileNames;

    public PrepareZipVisitor(ArrayList<String> fileNames)
    {
        this.fileNames = fileNames;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult visitFile(Path file, BasicFileAttributes basicFileAttributes) throws IOException
    {
        String name = file.getParent() + "/" + file.toFile().getName();
        this.fileNames.add(changeFileSeparator(name));
        return FileVisitResult.CONTINUE;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes basicFileAttributes) throws IOException
    {
        // is an empty directory, we need this especially if a CRL test does not have CRLs.
        if (dir.toFile().list() != null && dir.toFile().list().length == 0)
        {
            String name = dir.getParent() + "/" + dir.toFile().getName() + "/";
            this.fileNames.add(changeFileSeparator(name));
        }
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
        return FileVisitResult.CONTINUE;
    }

    private static String changeFileSeparator(String input) {
        return input.replaceAll(Pattern.quote("\\"), "/");
    }

}
