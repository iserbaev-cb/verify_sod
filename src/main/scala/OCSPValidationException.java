package nl.cleverbase.verify;

public class OCSPValidationException extends Exception{

    public OCSPValidationException(String msg, Throwable cause){
        super(msg, cause);
    }

    public OCSPValidationException(String msg) {
        super(msg);
    }

}
