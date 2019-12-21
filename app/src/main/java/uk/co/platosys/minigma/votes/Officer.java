package uk.co.platosys.minigma.votes;

import uk.co.platosys.minigma.Key;

/**
 *  Objects implementing the Officer interface represent the Returning Officer of a poll. Their Key is used
 *  to unwrap the Ballots sent to them by Voters.
 */

public interface Officer extends Voter {
    Key getKey();
}
