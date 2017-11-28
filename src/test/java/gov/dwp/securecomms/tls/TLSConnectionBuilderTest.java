package gov.dwp.securecomms.tls;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.SocketException;
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
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(MockitoJUnitRunner.class)
public class TLSConnectionBuilderTest {

    private final String CLIENT_TRUST_STORE_PATH = "src/test/resources/client-to-example-server-service-client.ts";
    private final String CLIENT_KEY_STORE_PATH = "src/test/resources/client-to-example-server-service-client.ks";
    private final String UNKNOWN_CLIENT_KEYSTORE_PATH = "src/test/resources/unknown-client.ks";
    private final String SERVER_TRUST_STORE_PATH = "src/test/resources/example-tls-server.ts";
    private final String SERVER_KEY_STORE_PATH = "src/test/resources/example-tls-server.ks";
    private final String TRUST_STORE_PASS = "password";
    private final String KEY_STORE_PASS = "password";

    private final String TRUST_ONLY_WEB_ENDPOINT = "https://127.0.0.1:7777/test";
    private final String MUTUAL_AUTH_WEB_ENDPOINT = "https://127.0.0.1:7778/test";

    @Rule
    public WireMockRule correctTrustAuthWireMock_SERVER = new WireMockRule(wireMockConfig()
            .port(6666)
            .httpsPort(7777)
            .needClientAuth(false)
            .trustStorePath(SERVER_TRUST_STORE_PATH)
            .trustStorePassword(TRUST_STORE_PASS)
            .keystorePath(SERVER_KEY_STORE_PATH)
            .keystorePassword(KEY_STORE_PASS)
    );

    @Rule
    public WireMockRule correctMutualAuthWireMock_SERVER = new WireMockRule(wireMockConfig()
            .port(6667)
            .httpsPort(7778)
            .needClientAuth(true)
            .trustStorePath(SERVER_TRUST_STORE_PATH)
            .trustStorePassword(TRUST_STORE_PASS)
            .keystorePath(SERVER_KEY_STORE_PATH)
            .keystorePassword(KEY_STORE_PASS)
    );

    @Rule
    public WireMockRule unknownTrustAuthWireMock_SERVER = new WireMockRule(wireMockConfig()
            .port(6668)
            .httpsPort(7779)
            .needClientAuth(false)
            .trustStorePath(SERVER_TRUST_STORE_PATH)
            .trustStorePassword(TRUST_STORE_PASS)
            .keystorePath(UNKNOWN_CLIENT_KEYSTORE_PATH)
            .keystorePassword(KEY_STORE_PASS)
    );

    @Test
    public void defaultSSLConnection() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(null, null, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));
        try {
            client.execute(httpUriRequest);
            fail("HTTPS request should not have been successful");

        } catch (IOException e) {
            assertThat("Should fail with validator.ValidatorException error", e.getMessage().contains("validator.ValidatorException"), is(true));
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void badTrustStorePath() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder("/bad-path/trustStore.ts", TRUST_STORE_PASS);
        try {
            testClass.configureSSLConnection();
            fail("HTTPS request should not have been successful");

        } catch (TLSGeneralException e) {
            assertThat("Should fail with tls.TLSGeneralException error", e.getMessage().contains("TLS Exception"), is(true));
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void badTrustStorePassword() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, "badpassword");
        try {
            testClass.configureSSLConnection();
            fail("HTTPS request should not have successful");

        } catch (IOException e) {
            assertThat("Should fail with io.IOException error", e.getCause().toString().contains("Password verification failed"), is(true));
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void validTrustStoreSSLConnection() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test
    public void invalidTrustStoreSSLConnection() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(MUTUAL_AUTH_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));
        try {
            client.execute(httpUriRequest);
            fail("authenticated secure connection should fail due to no keystore elements");

        } catch (SocketException e) {
            assertThat("Should get an aborted connection from the server", e.getMessage().contains("Software caused connection abort"), is(true));
            System.out.println(e.getMessage());
        } catch (SSLHandshakeException e) {
            assertThat("SSLHandshake error thrown before IOException for mac/redhat from the server", e.getMessage().contains("Remote host closed connection"), is(true));
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void badKeyStorePath() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, "/bad-path/keyStore.ks", KEY_STORE_PASS);
        try {
            testClass.configureSSLConnection();
            fail("should fail with bad keystore path");

        } catch (TLSGeneralException e) {
            assertThat("should fail with bad TLSGeneralException", e.getMessage().contains("TLS Exception"), is(true));
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void badKeyStorePassword() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, CLIENT_KEY_STORE_PATH, "badpassword");
        try {
            testClass.configureSSLConnection();
            fail("HTTPS request should not have successful");

        } catch (IOException e) {
            assertThat("Should fail with io.IOException error", e.getCause().toString().contains("Password verification failed"), is(true));
            System.out.println(e.getMessage());
        }
    }


    @Test
    public void validTwoWaySSLConnection() throws Exception {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, CLIENT_KEY_STORE_PATH, KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(MUTUAL_AUTH_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctMutualAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test
    public void invalidTwoWaySSLConnectionUnknownClientCert() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException, IOException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, UNKNOWN_CLIENT_KEYSTORE_PATH, KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(MUTUAL_AUTH_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctMutualAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));

        try {
            client.execute(httpUriRequest);
            fail("should fail on handshake");

        } catch (IOException e) {
            assertThat("should fail with handshake", e.getMessage(), is(equalTo("Remote host closed connection during handshake")));
        }
    }

    @Test
    public void invalidOneWaySSLConnectionWithUnknownServerCert() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder("src/test/resources/unknown-client.ts", TRUST_STORE_PASS, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        try {
            client.execute(httpUriRequest);
            fail("should fail with handshake");

        } catch (IOException e) {
            assertThat("should fail with handshake error", e.getMessage(), containsString("unable to find valid certification path to requested target"));
        }
    }

    @Test
    public void invalidOneWaySSLConnectionWithUnknownServerCertSent_FromServer() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, TLSGeneralException {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();

        HttpPost httpUriRequest = new HttpPost("https://127.0.0.1:7779/test");
        httpUriRequest.setEntity(new StringEntity("{}"));

        unknownTrustAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));

        try {
            client.execute(httpUriRequest);
            fail("should fail with handshake");

        } catch (IOException e) {
            assertThat("should fail with handshake error", e.getMessage(), containsString("unable to find valid certification path to requested target"));
        }
    }

    @Test
    public void validOneWaySSLConnection() throws Exception {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, null, null);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test
    public void validOneWaySSLConnectionWithNullKeystore() throws Exception {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, null, KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }

    @Test
    public void validOneWaySSLConnectionWithEmptyKeystore() throws Exception {
        TLSConnectionBuilder testClass = new TLSConnectionBuilder(CLIENT_TRUST_STORE_PATH, TRUST_STORE_PASS, "", KEY_STORE_PASS);
        CloseableHttpClient client = testClass.configureSSLConnection();
        HttpPost httpUriRequest = new HttpPost(TRUST_ONLY_WEB_ENDPOINT);
        httpUriRequest.setEntity(new StringEntity("{}"));

        correctTrustAuthWireMock_SERVER.stubFor(post(urlEqualTo("/test")).willReturn(aResponse().withStatus(200)));
        CloseableHttpResponse response = client.execute(httpUriRequest);
        assertThat("200 is expected for this path", response.getStatusLine().getStatusCode(), is(200));
    }
}