package uk.gov.dwp.tls;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.dwp.crypto.SecureStrings;

import javax.crypto.SealedObject;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class TLSConnectionBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(TLSConnectionBuilder.class.getName());
    private static final SecureStrings secureCipher = new SecureStrings();
    private String trustStoreFile;
    private SealedObject trustStorePassword;
    private SealedObject keyStorePassword;
    private String keyStoreFile;

    /**
     * Constructor for 2 way secure TLS connection using a trust store (with associated password) to verify the server certificate
     * and a keystore (with password) to pass back to the server for server-based mutual certificate trust authentication
     *
     * @param trustStoreFilename - relative or fully qualified path and name of the trust store
     * @param trustStorePassword - trust store password
     * @param keyStoreFilename   - relative or fully qualified path and name of the key store
     * @param keyStorePassword   - the key store password
     */
    public TLSConnectionBuilder(String trustStoreFilename, String trustStorePassword, String keyStoreFilename, String keyStorePassword) {
        this.trustStorePassword = secureCipher.sealString(trustStorePassword);
        this.keyStorePassword = secureCipher.sealString(keyStorePassword);
        this.trustStoreFile = trustStoreFilename;
        this.keyStoreFile = keyStoreFilename;
    }

    /**
     * Constructor for one way server authentication.  This connection verifies the endpoint is trust worthy by checking the trust store
     * for known certificates or signing authorities
     * against
     *
     * @param trustStoreFilename - relative or fully qualified path and name of the trust store
     * @param trustStorePassword - trust store password
     */
    public TLSConnectionBuilder(String trustStoreFilename, String trustStorePassword) {
        this.trustStorePassword = secureCipher.sealString(trustStorePassword);
        this.trustStoreFile = trustStoreFilename;
    }

    /**
     * Builds and configures the sslContext using the class properties and settings
     * <p>
     * If the keystore file path or the truststore file path are null or empty they will
     * not be included as part of the SSL context setup.  If the path is not null it will
     * be checked for validity with a TLS exception being thrown if the path does not point
     * to a real file.
     *
     * @return The configured sslContext object
     * @throws KeyStoreException         - keystore is not correctly configured
     * @throws IOException               - truststore/keystore files do not exist
     * @throws CertificateException      - bad cert
     * @throws NoSuchAlgorithmException  - bad cert
     * @throws UnrecoverableKeyException - keystore internal error
     * @throws KeyManagementException    - general keystore exception
     * @throws TLSGeneralException       - TLSConnectionBuilder exception
     */
    public SSLContext createAndPopulateContext() throws NoSuchAlgorithmException, KeyStoreException, TLSGeneralException, IOException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        TrustManagerFactory trustStoreManager = null;
        KeyManagerFactory keyStoreManager = null;
        KeyStore clientKeyStore = null;
        KeyStore trustStore = null;

        if ((getTrustStoreFile() != null) && (getTrustStoreFile().trim().length() > 0)) {
            trustStoreManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(new FileInputStream(checkFile(getTrustStoreFile())), getTrustStorePassword().toCharArray());
            trustStoreManager.init(trustStore);
        } else {
            LOG.info("Cannot use TRUSTSTORE, proceeding without trust anchors.  It is blank or null");
        }

        if ((getKeyStoreFile() != null) && (getKeyStoreFile().trim().length() > 0)) {
            keyStoreManager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            clientKeyStore.load(new FileInputStream(checkFile(getKeyStoreFile())), getKeyStorePassword().toCharArray());
            keyStoreManager.init(clientKeyStore, getKeyStorePassword().toCharArray());
        } else {
            LOG.info("Cannot use KEYSTORE, proceeding without keystore.  It is blank or null");
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init((clientKeyStore == null) ? null : keyStoreManager.getKeyManagers(),
                (trustStore == null) ? null : trustStoreManager.getTrustManagers(),
                new SecureRandom());

        return sslContext;
    }

    /**
     * Builds and configures the TLS connection based on the available set-up parameters
     * <p>
     * If the keystore file path or the truststore file path are null or empty they will
     * not be included as part of the SSL context setup.  If the path is not null it will
     * be checked for validity with a TLS exception being thrown if the path does not point
     * to a real file.
     * s
     *
     * @return The configured secure Https client connection
     * @throws KeyStoreException         - keystore is not correctly configured
     * @throws IOException               - truststore/keystore files do not exist
     * @throws CertificateException      - bad cert
     * @throws NoSuchAlgorithmException  - bad cert
     * @throws UnrecoverableKeyException - keystore internal error
     * @throws KeyManagementException    - general keystore exception
     * @throws TLSGeneralException       - TLSConnectionBuilder exception
     */
    public CloseableHttpClient configureSSLConnection() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException, TLSGeneralException {
        HttpClientBuilder builder = HttpClientBuilder.create();
        builder.setSSLContext(createAndPopulateContext());
        return builder.build();
    }

    /**
     * Check the file name and paths are correct
     *
     * @param fileName - the file (including path) to check
     * @return The file object
     * @throws TLSGeneralException
     */
    private File checkFile(String fileName) throws TLSGeneralException {
        File fileObject = new File(fileName);
        if (!fileObject.exists()) {
            throw new TLSGeneralException(String.format("%s does not exist", fileName));
        }
        return fileObject;
    }

    public String getTrustStoreFile() {
        return trustStoreFile;
    }

    public String getTrustStorePassword() {
        return secureCipher.revealString(trustStorePassword);
    }

    public String getKeyStorePassword() {
        return secureCipher.revealString(keyStorePassword);
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }
}
