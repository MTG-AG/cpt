
package de.mtg.certpathtest.pkiobjects;

import java.io.StringWriter;
import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class CRL
{

    private String id;

    private String location;
    private String verifiedBy;
    private String version;
    private String signature;
    private IssuerDN issuerDN;
    private ThisUpdate thisUpdate;
    private NextUpdate nextUpdate;
    private ArrayList<RevokedCertificate> revokedCertificates = new ArrayList<>();
    private ArrayList<Extension> extensions = new ArrayList<>();
    private Modification modification;

    public CRL()
    {

    }

    public String getId()
    {
        return id;
    }

    @XmlAttribute
    public void setId(String id)
    {
        this.id = id;
    }

    public String getVerifiedBy()
    {
        return verifiedBy;
    }

    @XmlElement(name = "VerifiedBy")
    public void setVerifiedBy(String verifiedBy)
    {
        this.verifiedBy = verifiedBy;
    }

    public String getLocation()
    {
        return location;
    }

    @XmlElement(name = "Location")
    public void setLocation(String location)
    {
        this.location = location;
    }

    public String getVersion()
    {
        return version;
    }

    @XmlElement(name = "Version")
    public void setVersion(String version)
    {
        this.version = version;
    }

    public String getSignature()
    {
        return signature;
    }

    @XmlElement(name = "Signature")
    public void setSignature(String signature)
    {
        this.signature = signature;
    }

    public IssuerDN getIssuerDN()
    {
        return issuerDN;
    }

    @XmlElement(name = "IssuerDN")
    public void setIssuerDN(IssuerDN issuerDN)
    {
        this.issuerDN = issuerDN;
    }

    public ThisUpdate getThisUpdate()
    {
        return thisUpdate;
    }

    @XmlElement(name = "ThisUpdate")
    public void setThisUpdate(ThisUpdate thisUpdate)
    {
        this.thisUpdate = thisUpdate;
    }

    public NextUpdate getNextUpdate()
    {
        return nextUpdate;
    }

    @XmlElement(name = "NextUpdate")
    public void setNextUpdate(NextUpdate nextUpdate)
    {
        this.nextUpdate = nextUpdate;
    }

    public ArrayList<RevokedCertificate> getRevokedCertificates()
    {
        return revokedCertificates;
    }

    @XmlElement(name = "RevokedCertificate")
    public void setRevokedCertificates(ArrayList<RevokedCertificate> revokedCertificates)
    {
        this.revokedCertificates = revokedCertificates;
    }

    public ArrayList<Extension> getExtensions()
    {
        return extensions;
    }

    @XmlElement(name = "Extension")
    public void setExtensions(ArrayList<Extension> extensions)
    {
        this.extensions = extensions;
    }

    public Modification getModification()
    {
        return modification;
    }

    @XmlElement(name = "Modification")
    public void setModification(Modification modification)
    {
        this.modification = modification;
    }

    @Override
    public String toString()
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(CRL.class);
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