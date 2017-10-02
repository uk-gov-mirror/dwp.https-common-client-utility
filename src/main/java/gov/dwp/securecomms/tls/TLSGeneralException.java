package gov.dwp.securecomms.tls;

public class TLSGeneralException extends Exception {
    public TLSGeneralException(String message) {
        super(String.format("TLS Exception :: %s", message));
    }
}
