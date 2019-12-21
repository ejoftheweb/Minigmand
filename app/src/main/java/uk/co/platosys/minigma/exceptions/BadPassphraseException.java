package uk.co.platosys.minigma.exceptions;

public class BadPassphraseException extends MinigmaException {
    public BadPassphraseException(String msg){
        super(msg);
    }
    public BadPassphraseException(String msg, Throwable cause){
        super(msg, cause);
    }
}
