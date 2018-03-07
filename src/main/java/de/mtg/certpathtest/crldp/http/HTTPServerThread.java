
package de.mtg.certpathtest.crldp.http;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ConfigurationProperties;
import de.mtg.certpathtest.Utils;

/**
 *
 * The thread where the HTTP server for the revocation list distribution runs.
 *
 */
public class HTTPServerThread extends Thread
{

    private static Logger logger = LoggerFactory.getLogger(HTTPServerThread.class);

    /**
     *
     * {@inheritDoc}
     */
    public void run()
    {

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();

        String host = configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_HOST);

        String port = configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_PORT);

        String resourcesDirectory =
            configurationProperties.getProperties().getString(ConfigurationProperties.HTTP_RESOURCES_DIR);

        Server server = new Server();
        ServerConnector serverConnector = new ServerConnector(server);
        serverConnector.setHost(host);
        serverConnector.setPort(Integer.parseInt(port));
        server.addConnector(serverConnector);

        ServletHandler servletHandler = new ServletHandler();
        server.setHandler(servletHandler);

        ResourceHandler resourceHandler = new ResourceHandler();

        resourceHandler.setDirectoriesListed(true);
        resourceHandler.setResourceBase(resourcesDirectory);

        HandlerList handlerList = new HandlerList();
        handlerList.setHandlers(new Handler[] {resourceHandler, new DefaultHandler()});
        server.setHandler(handlerList);

        try
        {
            server.start();
            server.join();
        }
        catch (Exception e)
        {
            Utils.logError("Could not start HTTP Server. Please check if another instance of the server is running.");
            logger.debug("", e);
        }

    }

}
