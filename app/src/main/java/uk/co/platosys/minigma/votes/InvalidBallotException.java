package uk.co.platosys.minigma.votes;

public class InvalidBallotException extends Exception {
    public InvalidBallotException(String msg) {
        super(msg);
    }
}