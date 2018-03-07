
package de.mtg.certpathtest.crldp;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mtg.certpathtest.ConfigurationProperties;

/**
 *
 * Object of this class represent a GUI window that allows to stop the application and shows the status of the servers
 * used in the tool.
 *
 */
public class StopApplicationWindow
{

    private static Logger logger = LoggerFactory.getLogger(StopApplicationWindow.class);

    private JLabel ldapStatus;
    private JLabel httpStatus;

    /**
     *
     * Returns the GUI element representing the status of the LDAP server. This can be used for updating the text and
     * the icon from the caller to represent changes in the state of the server.
     *
     * @return the GUI element representing the status of the LDAP server.
     */
    public JLabel getLDAPStatus()
    {
        return ldapStatus;
    }

    /**
     *
     * Returns the GUI element representing the status of the HTTP server. This can be used for updating the text and
     * the icon from the caller to represent changes in the state of the server.
     *
     * @return the GUI element representing the status of the HTTP server.
     */
    public JLabel getHTTPStatus()
    {
        return httpStatus;
    }

    /**
     *
     * Constructs a newly allocated StopApplicationWindow object.
     *
     */
    public StopApplicationWindow()
    {

        ConfigurationProperties configurationProperties = ConfigurationProperties.getInstance();
        boolean showGUi = configurationProperties.getProperties().getBoolean(ConfigurationProperties.SHOW_GUI);

        if (showGUi)
        {

            JFrame frame = new JFrame();

            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setTitle("Certification Path Test");
            frame.setResizable(false);
            frame.setSize(300, 200);

            frame.setLocationRelativeTo(null);

            final JPanel panel = new JPanel();
            panel.setLayout(new GridBagLayout());

            GridBagConstraints c = new GridBagConstraints();
            c.fill = GridBagConstraints.HORIZONTAL;
            c.insets = new Insets(10, 10, 10, 10);
            c.gridx = 0;
            c.gridy = 0;

            JButton stopApplicationButton = new JButton("Stop Application");

            panel.add(stopApplicationButton, c);

            boolean useLDAP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.LDAP_USE);
            boolean useHTTP = configurationProperties.getProperties().getBoolean(ConfigurationProperties.HTTP_USE);

            String httpMessage = "";

            if (useHTTP)
            {
                httpMessage = "HTTP server is starting...";
            }
            else
            {
                httpMessage = "HTTP server is not configured.";
            }

            String ldapMessage = "";

            if (useLDAP)
            {
                ldapMessage = "LDAP server is starting...";
            }
            else
            {
                ldapMessage = "LDAP server is not configured.";
            }

            httpStatus = new JLabel(httpMessage, new ImageIcon("resources/yellow.png"), JLabel.LEFT);
            ldapStatus = new JLabel(ldapMessage, new ImageIcon("resources/yellow.png"), JLabel.LEFT);

            Thread healthCheckThread = new HealthCheckThread(this);
            healthCheckThread.start();

            c.gridx = 0;
            c.gridy = 1;
            panel.add(httpStatus, c);

            c.anchor = GridBagConstraints.FIRST_LINE_START;
            c.gridx = 0;
            c.gridy = 2;
            panel.add(ldapStatus, c);

            stopApplicationButton.addActionListener(new ActionListener()
            {
                @Override
                public void actionPerformed(ActionEvent ae)
                {
                    logger.info("Stopping the application over the window.");
                    logger.info("Program finished.");
                    System.exit(0);
                }
            });

            frame.add(panel, BorderLayout.LINE_START);

            frame.setVisible(true);
        }
    }

}