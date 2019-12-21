package uk.co.platosys.minigma.votes;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import uk.co.platosys.minigma.BigBinary;
import uk.co.platosys.minigma.Signature;

/**A poll consists of a collection of votes. The Poll allocates a Ballot to every Voter in the Electorate, collects them afterwards and processes
 * the results.
 * To use: instantiate a Poll, giving an int as a poll id. Up to you to manage the recording and allocation of these IDs.
 * conflicting poll IDs in an application could give unpredictable results.
 * Call the Poll using the call method.
 *
 * the state of the Poll object must be preserved after calling the call() method until closeOfPoll. Hence this
 * class implements Serializable.
 *
 */
public class Poll implements Serializable {
    int pollid;
    private List<BigBinary> ballots = new ArrayList<>();
    int[] results;
    Date closeOfPoll;
    int resultIndex=0;

    public Poll (int pollid, Date closeOfPoll) {
       this.pollid=pollid;
       this.closeOfPoll=closeOfPoll;
    }


    /**Method to set the process in motion.
     * The Electorate object is a Set of Voters and each member of the Set will be modified by this
     * method, through the notify() method.
     * The returned List of BigBinaries is a list of the tokens sent with each ballot, but they cannot
     * reasonably be mapped to the voters to whom each one is sent.
     *
     * @param electorate The electorate being polled.
     * @param officer The Returning Officer responsible for the poll
     * @param passphrase The officer's passphrase (
     * @return a List of BigBinary numbers.       *
     */
    public List<BigBinary> call(Electorate electorate, Officer officer, char[] passphrase){
        //ballots=new BigBinary[electorate.size()];
        results=new int[electorate.size()];
        SecureRandom secureRandom = new SecureRandom();//RNG to generate the poll tokens
        for (Voter voter:electorate){
            Ballot ballot = Ballot.create(this, secureRandom);
            BigBinary serialisedBallot = ballot.serialiseBlank();
            try {

                Signature signature = officer.getKey().sign(serialisedBallot, passphrase);
                voter.notify(voter.getLock().lock(serialisedBallot), officer, signature );
                ballots.add(ballot.getToken());

            }catch(Exception x){
                //TODO
                //Log IT
            }

        }
        //ballots.sort(); Need to implement BigBinary's comparable first.
        return ballots;



    }
    /**BigBinary voting papers are received from voters, encrypted with the officer's Key.*/
    public void recordVote(BigBinary paper, Officer officer, char[] passphrase) throws InvalidBallotException {
        if (new Date().getTime()>closeOfPoll.getTime()){throw new InvalidBallotException ("out of time, poll has closed");}
        try {//first decrypt the paper.
            BigBinary clearpaper = officer.getKey().unlock(paper, passphrase);
            Ballot voted = new Ballot(clearpaper, pollid, true);
            BigBinary token = voted.getToken();
            if (ballots.contains(token)){
                results[resultIndex]=voted.getVote();
                ballots.remove(token);
                resultIndex++;
            }else{
                throw new InvalidBallotException("ballot contains invalid token");
            }

        }catch(Exception x){
            //TODO
        }

    }

    /**returns an array of ints with the results of the poll, after the close of poll. Before the close of poll,
     * returns null
     * @return
     */
    public int[] getResult(){
        Date now = new Date();
        if (now.getTime()>closeOfPoll.getTime()) {
            return results;
        }else{
            return null;
        }
    }
}
