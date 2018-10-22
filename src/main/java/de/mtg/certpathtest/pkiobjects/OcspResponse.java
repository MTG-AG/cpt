
package de.mtg.certpathtest.pkiobjects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.StringWriter;
import java.util.ArrayList;

@XmlRootElement
public class OcspResponse
{

    private String id;
    private String responseStatus;
    private String ocspCertId;

    private String location;
    private String verifiedBy;
    private String version;
    private String signature;
    private ResponderId responderId;
    private ResponseEntry responseEntry;
    private ProducedAt producedAt;
    private ArrayList<RevokedCertificate> revokedCertificates = new ArrayList<>();
    private ArrayList<Extension> extensions = new ArrayList<>();
    private Modification modification;

    public OcspResponse()
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

    public String getResponseStatus()
    {
        return responseStatus;
    }

    @XmlAttribute
    public void setResponseStatus(String responseStatus)
    {
        this.responseStatus = responseStatus;
    }

    public String getOcspCertId()
    {
        return ocspCertId;
    }

    @XmlAttribute
    public void setOcspCertId(String ocspCertId)
    {
        this.ocspCertId = ocspCertId;
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

    public ResponderId getResponderId()
    {
        return responderId;
    }

    @XmlElement(name = "ResponderId")
    public void setResponderId(ResponderId responderId)
    {
        this.responderId = responderId;
    }

    public ResponseEntry getResponseEntry()
    {
        return responseEntry;
    }

    @XmlElement(name = "ResponseEntry")
    public void setResponseEntry(ResponseEntry responseEntry)
    {
        this.responseEntry = responseEntry;
    }

    public ProducedAt getProducedAt()
    {
        return producedAt;
    }

    @XmlElement(name = "ProducedAt")
    public void setProducedAt(ProducedAt producedAt)
    {
        this.producedAt = producedAt;
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
            JAXBContext jaxbContext = JAXBContext.newInstance(OcspResponse.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
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