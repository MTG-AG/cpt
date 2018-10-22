package de.mtg.certpathtest.crldp.http;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import de.mtg.certpathtest.ObjectCache;
import de.mtg.certpathtest.TestToolOCSPResponse;
import de.mtg.certpathtest.pkiobjects.OcspResponse;
import org.eclipse.jetty.http.HttpStatus;

public class OCSPServlet extends HttpServlet
{

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {

        try
        {
            // ignore the real content of the OCSP request
            // InputStream is = request.getInputStream();
            // byte[] bytes = IOUtils.toByteArray(is);
            // but use the mapping over the location to locate the correct OCSP response.

            String path = request.getPathInfo();

            ObjectCache objectCache = ObjectCache.getInstance();

            // if no dynamic requests are created.
            //byte[] rawOCSPResponse = objectCache.getRawOcspResponse("CERT_PATH_OCSP_01_EE_RESP");

            String ocspResponseID = objectCache.getOcspAIAs().get(path.trim());
            OcspResponse xmlOcspResponse = objectCache.getOcspResponse(ocspResponseID);

            TestToolOCSPResponse testToolOCSPResponse = new TestToolOCSPResponse();
            testToolOCSPResponse.createOCSPResponse(xmlOcspResponse);

            if (testToolOCSPResponse.getEncoded() != null) {
                response.setStatus(HttpStatus.OK_200);
                response.setContentType(org.eclipse.jetty.http.MimeTypes.Type.TEXT_HTML_UTF_8.asString());
                response.getOutputStream().write(testToolOCSPResponse.getEncoded());
                response.getOutputStream().flush();
            }
            else {
                response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR_500);
                response.setContentType(org.eclipse.jetty.http.MimeTypes.Type.TEXT_HTML_UTF_8.asString());
                response.getOutputStream().flush();
            }
        }
        catch (Exception ex)
        {
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR_500);
            response.setContentType(org.eclipse.jetty.http.MimeTypes.Type.TEXT_HTML_UTF_8.asString());
            response.getOutputStream().flush();
        }


    }

    /**
     * {@inheritDoc}
     */
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        doGet(request, response);
    }


}
