package uk.co.platosys.minigma.votes;
import uk.co.platosys.minigma.BigBinary;
/**
 * The Ballot models the actual little ball of paper that gets put into the urn. Or whatever.
 * The Ballot consists of a BigBinary token, to which an int is appended as a vote. It
 * is up to the application to decide on the significance of the possible votes - with an int, there are 2^32 possible
 * values which should be enough and you will probably want to restrict them - to, for example, just two in the case of a yes/no
 * referendum. However the vote value 0 is restricted to a blank vote.
 */
public class Ballot  {
    public static final int BLANK=0;
    private BigBinary token;
    private int vote=BLANK;
    int pollid;
    private Ballot (int pollid){
        this.pollid=pollid;
    }

    /**the client app instantiates a Ballot from a BigBinary consisting of the
     * ballot token concatenated with the pollid, which is what is returned by the
     * serialiseBlank() method. The Voter will have to unlock what has been sent to them
     * with their private key.
     * @param paper
     * @param pollid
     * @throws InvalidBallotException
     */
    public Ballot(BigBinary paper, int pollid) throws InvalidBallotException {
        int test = paper.detachInt();
        if (test!=pollid){throw new InvalidBallotException("poll ids don't match");}
        this.pollid=pollid;
        this.token=paper;
    }

    /**this method is called by the Poll once the ballot has been created. The resultant
     * BigBinary is encrypted with the Voter's public Lock so it can only be unlocked by them. It should
     * also be signed with the Officer's private Key.
     * @return
     */
    public BigBinary serialiseBlank(){
        return token.append(pollid);
    }

    /**
     * this method is called by the client app after the vote(int) method has been called, and the resultant
     * BigBinary is then locked with the Officer's public Lock. It *SHOULD NOT BE SIGNED*
     * If it is called before the vote(int) method the result will be a blank vote.
     * @return
     */
    public BigBinary serialiseVoted(){
        return token.append(vote).append(pollid);
    }
    public void vote(int vote){
        this.vote=vote;
    }
    public static Ballot create(Poll poll){
        return new Ballot(poll.pollid);
    }
    protected BigBinary getToken(){
        return token;
    }

}