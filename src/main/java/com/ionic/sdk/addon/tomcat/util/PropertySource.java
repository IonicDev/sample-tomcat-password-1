package com.ionic.sdk.addon.tomcat.util;

import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.agent.AgentSdk;
import com.ionic.sdk.agent.cipher.chunk.ChunkCipherV3;
import com.ionic.sdk.agent.cipher.chunk.data.ChunkCrypto;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.error.IonicException;

import java.io.File;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Tomcat provides a means to modify default loading of its configuration at startup.  This class implements a Tomcat
 * extension point to allow the Ionic protection of properties in the Tomcat instance configuration.
 */
public final class PropertySource implements org.apache.tomcat.util.IntrospectionUtils.PropertySource {

    /**
     * Class scoped logger.
     */
    private final Logger logger = Logger.getLogger(getClass().getName());

    /**
     * Ionic platform point of interaction.
     */
    private Agent agent;

    /**
     * Constructor.
     * <p>
     * Initialize Ionic agent instance (to be used on "getProperty()" call).  The Ionic Secure Enrollment Profile is
     * assumed to be located in the "conf" directory of the Tomcat instance.
     */
    public PropertySource() {
        // find Ionic Profile
        final String catalinaHome = System.getProperty("catalina.home");
        final File ionicProfile = new File(catalinaHome, "conf/ionic.sep.plaintext.json");

        try {
            // load Ionic Profile
            AgentSdk.initialize(Security.getProvider("SunJCE"));

            final Level level = (ionicProfile.exists()) ? Level.INFO : Level.SEVERE;
            logger.log(level, "Ionic Secure Enrollment Profile resource path=[{0}]", ionicProfile.getPath());

            agent = new Agent(new DeviceProfilePersistorPlainText(ionicProfile.getPath()));
        } catch (IonicException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Interface point for implementation.  In this code sample, the {@link PropertySource} may be used to perform
     * Ionic encryption or decryption, based on the "key" parameter value.
     * <ul>
     * <li>To encrypt a string value, use the prefix "IonicEncrypt." prepended to the value to be encrypted.  For
     * example, to encrypt "helloworld", the parameterized value in the Tomcat configuration would be
     * "${IonicEncrypt.helloworld}".  The value will be written to stdout when the configuration file is read at
     * startup.</li>
     * <li>To decrypt a string value, use the Ionic ciphertext value.  The Tomcat configuration setting will look like
     * "${~!3!D7GH9_HYQls!wNpN248hw/H8Bl+tNedwGSMf9lhTyM33i4J4smI6bmJAGxk6!}".
     * </li>
     * <li>Any string that does not meet one of these criteria will use the Tomcat default, which is to perform a
     * "System.getProperty()" lookup, and return the result of the lookup.</li>
     * </ul>
     *
     * @param key the value to be resolved
     * @return the resolved value (either the result of the Ionic string operation, or the default behavior)
     */
    @Override
    public String getProperty(String key) {
        final String ionicPrefix = "IonicEncrypt.";
        if (key.startsWith(ionicPrefix)) {
            final String value = key.substring(ionicPrefix.length());
            logger.info(ionicPrefix + " = " + ionicEncrypt(value));
            return value;
        } else if (ChunkCrypto.getChunkInfo(key).isEncrypted()) {
            return ionicDecrypt(key);
        } else {
            return getPropertyDefault(key);
        }
    }

    /**
     * Encrypt value using Ionic SDK and platform.
     *
     * @param value plaintext value to be encrypted
     * @return Ionic ciphertext representation of value
     */
    private String ionicEncrypt(final String value) {
        try {
            return new ChunkCipherV3(agent).encrypt(value);
        } catch (IonicException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            return getPropertyDefault(value);
        }
    }

    /**
     * Decrypt value using Ionic SDK and platform.
     *
     * @param value the Ionic ciphertext value to be decrypted
     * @return plaintext representation of value
     */
    private String ionicDecrypt(final String value) {
        try {
            return new ChunkCipherV3(agent).decrypt(value);
        } catch (IonicException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            return getPropertyDefault(value);
        }
    }

    /**
     * Backstop function that implements default Tomcat behavior (query system property set for value of specified key).
     *
     * @param key the property key referencing the requested key/value pair
     * @return the property value of the referenced key
     */
    private String getPropertyDefault(final String key) {
        return System.getProperty(key);
    }
}
