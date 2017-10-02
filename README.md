## secure-sockets
An encapsulated class to manage the standard creation of single and mutually authenticated HTTPS connections.  Run with VM java options for extra debugging information of the secure socket transaction traffic.

`-Djava.security.debug=certpath -Djavax.net.debug=ssl`

#### Project inclusion

properties entry in pom

    <properties>
        <dwp.secure-sockets.version>x.x</dwp.secure-sockets.version>
    </properties>
    
internal Artifactory repository reference is required (plugin reference required for OWASP checks)

    <repositories>
        <repository>
            <id>dwp internal</id>
            <url>###REPOSITORY_URL###</url>
        </repository>
    </repositories>
    <pluginRepositories>
        <pluginRepository>
            <id>dwp internal</id>
            <url>###REPOSITORY_URL###</url>
        </pluginRepository>
    </pluginRepositories>

dependency reference

    <dependency>
        <groupId>dwp-utility</groupId>
        <artifactId>secure-sockets</artifactId>
        <version>${dwp.secure-sockets.version}</version>
    </dependency>
    
#### Example of use

    import gov.dwp.securecomms.tls.TLSConnectionBuilder;
    import gov.dwp.securecomms.tls.TLSGeneralException;

##### Target connection trust

Construct for one way server authentication that verifies the endpoint is trustworthy by checking the trust store for known certificates or signing authorities

`public TLSConnectionBuilder(String trustStoreFilename, String trustStorePassword)`

##### Mutually trust connection

Construct a 2 way (mutually) secure TLS connection using a trust store (with associated password) to verify the server certificate
and a keystore (with password) to present to target server for server-based mutual certificate trust authentication

`public TLSConnectionBuilder(String trustStoreFilename, String trustStorePassword, String keyStoreFilename, String keyStorePassword)`


