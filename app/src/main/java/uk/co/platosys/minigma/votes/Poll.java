package uk.co.platosys.minigma.votes;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import uk.co.platosys.minigma.BigBinary;

/**A poll consists of a collection of votes. The Poll allocates a Ballot to every Voter in the Electorate, collects them afterwards and processes
 * the results.
 * To use: instantiate a Poll, giving an int as a poll id. Up to you to manage the recording and allocation of these IDs.
 * conflicting poll IDs in an application could give unpredictable results.
 * Call the Poll using
 */
public class Poll implements Serializable {
    int pollid;
    private List<BigBinary> ballots = new ArrayList<>();
    int[] results;
    public Poll (int pollid){
        this.pollid=pollid;
    }

    public BigBinary[] call(Electorate electorate, Officer officer, char passphrase){
        //ballots=new BigBinary[electorate.size()];
        results=new int[electorate.size()];

        for (Voter voter:electorate){
            Ballot ballot = Ballot.create(this);
            BigBinary serialisedBallot = ballot.serialiseBlank();
            try {
                //TODO Should be signed by the Officer.
                voter.notify(voter.getLock().lock(serialisedBallot));
                ballots.add(ballot.getToken());
            }catch(Exception x){
                //TODO
                //Log IT
            }

        }
        return null;
        //ballots.toArray(? [extends BigBinary] bigBinary)


    }
    //BigBinary voting papers are received from voters, encrypted with the officer's Key.
    public void recordVote(BigBinary paper, Officer officer, char[] passphrase){

    }
    public int[] getResult(){
        //TODO
        return results;
    }
}
