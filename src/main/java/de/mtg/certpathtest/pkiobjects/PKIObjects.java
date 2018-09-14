
package de.mtg.certpathtest.pkiobjects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.StringWriter;
import java.util.ArrayList;

@XmlRootElement(name = "PKIObjects")
public class PKIObjects
{

    private ArrayList<Variable> variables = new ArrayList<>();
    private ArrayList<Certificate> certificates = new ArrayList<>();
    private ArrayList<CRL> revocationLists = new ArrayList<>();

    public PKIObjects()
    {

    }

    public ArrayList<Variable> getVariables()
    {
        return this.variables;
    }

    @XmlElement(name = "Variable")
    public void setVariables(ArrayList<Variable> variables)
    {
        this.variables = variables;
    }

    public ArrayList<Certificate> getCertificates()
    {
        return certificates;
    }

    @XmlElement(name = "Certificate")
    public void setCertificates(ArrayList<Certificate> certificates)
    {
        this.certificates = certificates;
    }

    public ArrayList<CRL> getCRLs()
    {
        return this.revocationLists;
    }

    @XmlElement(name = "CRL")
    public void setCRLs(ArrayList<CRL> revocationLists)
    {
        this.revocationLists = revocationLists;
    }

    @Override
    public String toString()
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(PKIObjects.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_ENCODING, "UTF-8");
            marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            StringWriter stringWriter = new StringWriter();
            marshaller.marshal(this, stringWriter);
            stringWriter.flush();
            stringWriter.close();
            return stringWriter.toString();
        }
        catch (Exception e)
        {
            return "";
        }

    }

}