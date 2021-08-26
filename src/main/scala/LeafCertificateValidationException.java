package nl.cleverbase.verify;

public class LeafCertificateValidationException extends Exception{

    public LeafCertificateValidationException(String msg, Throwable cause){
        super(msg,cause);
    }

    public LeafCertificateValidationException(String msg) {
        super(msg);
    }
}
