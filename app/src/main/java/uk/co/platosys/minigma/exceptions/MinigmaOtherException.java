package uk.co.platosys.minigma.exceptions;

public class MinigmaOtherException extends MinigmaException {
    public MinigmaOtherException(String msg){
        super(msg);
    }
    public MinigmaOtherException(String msg, Throwable cause){
        super(msg, cause);
    }
}
