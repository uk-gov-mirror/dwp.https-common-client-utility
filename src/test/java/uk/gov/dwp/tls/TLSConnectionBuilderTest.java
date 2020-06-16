package uk.gov.dwp.tls;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@SuppressWarnings("squid:S1192") // allow string literals in tests
@RunWith(MockitoJUnitRunner.class)
public class TLSConnectionBuilderTest {

    private static final String CLIENT_TRUST_STORE_PATH = "src/test/resources/client-to-example-server-service-client.ts";
    private static final String CLIENT_KEY_STORE_PATH = "src/test/resources/client-to-example-server-service-client.ks";
    private static final String UNKNOWN_CLIENT_KEYSTORE_PATH = "src/test/resources/unknown-client.ks";
    private static final String SERVER_TRUST_STORE_PATH = "src/test/resources/example-tls-server.ts";
    private static final String SERVER_KEY_STORE_PATH = "src/test/resources/example-tls-server.ks";
    private static final String TRUST_STORE_PASS = "password";
    private static final String KEY_STORE_PASS = "password";

    private static final String TRUST_ONLY_WEB_ENDPOINT = "https://127.0.0.1:7777/test";
    private static final String MUTUAL_AUTH_WEB_ENDPOINT = "https://127.0.0.1:7778/test";

    @Rule
    public WireMockRule correctTrustAuthWireMockServer = new WireMockRule(wireMockConfig()
            .port(6666)
            .httpsPort(7777)
            .needClientAuth(false)
            .trustStorePath(SERVER_TRUST_STORE_PATH)
            .trustStorePassword(TRUST_STORE_PASS)
            .keystorePath(SERVER_KEY_STORE_PATH)
            .keystorePassword(KEY_STORE_PASS)
    );

    @Rule
    public WireMockRule correctMutualAuthWireMockServer = new WireMockRule(wireMockConfig()
            .port(6667)
            .httpsPort(7778)
            .needClientAuth(true)
            .trustStorePath(SERVER_TRUST_STORE_PATH)
            .trustStorePassword(TRUST_STORE_PASS)
            .keystorePath(SERVER_KEY_STORE_PATH)
            .keystorePassword(KEY_STORE_PASS)
    );

    @Rule
    public WireMockRule unknownTrustAuthWireMockServer = new WireMockRule(wireMockConfig()
            .port(6668)
            .httpsPort(7779)
            .needClientAuth(false)
            .trustStorePath(SERVER_TRUST_STORE_PATH)
            .trustStorePassword(TRUST_STORE_PASS)
            .keystorePath(UNKNOWN_CLIENT_KEYSTORE_PATH)
            .keystorePassword(KEY_STORE_PASS)
    );

    @Test(expected = IOException.class)
    public void defaultSSLConnection() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(null, null, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        client.execute(httpUriRequest);
    }

    @Test
    public void badTrustStorePath() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder("/bad-path/trustStore.ts", TRUST_STORE_PASS);
        try {
            testClass.configureSSLConnection();
            fail("HTTPS request should not have been successful");

        } catch (TLSGeneralException e) {
            assertThat("Should fail with tls.TLSGeneralException error", e.getMessage().contains("TLS Exception"), is(true));
        }
    }

    @Test
    public void badTrustStorePassword() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, IOException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, "badpassword");
        try {
            testClass.configureSSLConnection();
            fail("HTTPS request should not have successful");

        } catch (IOException e) {
            assertThat("Should fail with io.IOException error", e.getCause().toString().contains("Password verification failed"), is(true));
        }
    }

    @Test
    public void validTrustStoreSSLConnection() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test(expected = IOException.class)
    public void invalidTrustStoreSSLConnection() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(MUTUAL_AUTH_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        client.execute(httpUriRequest);
    }

    @Test
    public void badKeyStorePath() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, "/bad-path/keyStore.ks", KEY_STORE_PASS);
        try {
            testClass.configureSSLConnection();
            fail("should fail with bad keystore path");

        } catch (TLSGeneralException e) {
            assertThat("should fail with bad TLSGeneralException", e.getMessage().contains("TLS Exception"), is(true));
        }
    }

    @Test
    public void badKeyStorePassword() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, IOException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, CLIENT_KEY_STORE_PATH, "badpassword");
        try {
            testClass.configureSSLConnection();
            fail("HTTPS request should not have successful");

        } catch (IOException e) {
            assertThat("Should fail with io.IOException error", e.getCause().toString().contains("Password verification failed"), is(true));
        }
    }


    @Test
    public void validTwoWaySSLConnection() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, CLIENT_KEY_STORE_PATH, KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(MUTUAL_AUTH_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctMutualAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test(expected = IOException.class)
    public void invalidTwoWaySSLConnectionUnknownClientCert() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, UNKNOWN_CLIENT_KEYSTORE_PATH, KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(MUTUAL_AUTH_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctMutualAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        client.execute(httpUriRequest);
    }

    @Test
    public void invalidOneWaySSLConnectionWithUnknownServerCert() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder("src/test/resources/unknown-client.ts", TRUST_STORE_PASS, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        try {
            client.execute(httpUriRequest);
            fail("should fail with handshake");

        } catch (IOException e) {
            assertThat("should fail with handshake error", e.getMessage(), containsString("unable to find valid certification path to requested target"));
        }
    }

    @Test
    public void invalidOneWaySSLConnectionWithUnknownServerCertSentFromServer() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();

        HttpPost httpUriRequest = new HttpPost("https://127.0.0.1:7779/test");
        httpUriRequest.setEntity(new StringEntity("{}"));

        unknownTrustAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));

        try {
            client.execute(httpUriRequest);
            fail("should fail with handshake");

        } catch (IOException e) {
            assertThat("should fail with handshake error", e.getMessage(), containsString("unable to find valid certification path to requested target"));
        }
    }

    @Test
    public void validOneWaySSLConnection() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test
    public void validOneWaySSLConnectionWithNullKeystore() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, null, KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test
    public void validOneWaySSLConnectionWithEmptyKeystore() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, "", KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMockServer.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }
}
