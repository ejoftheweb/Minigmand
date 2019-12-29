package uk.co.platosys.minigma.votes;

import uk.co.platosys.minigma.BigBinary;
import uk.co.platosys.minigma.Lock;
import uk.co.platosys.minigma.Signature;

/**
 * Objects implementing this interface represent voters (duh).  You would probably want to implement
 * it in your application's 'user' objects.
 */
public interface Voter {
     Lock getLock();

     /**
      * Returns the encrypted voting paper to be sent to the voter.
      * @return
      */
     BigBinary getPaper();

     /**
      * Returns the signature of the Returning Officer as applied to the voter's ballot.

      * @return
      */
     Signature getPollSignature();

     /**Called by the Poll object when a poll is called. The BigBinary passed as an argument is
      * the Ballot, encrypted with the Voter's public Lock. It is accompanied by the Signature of the
      * poll's Returning Officer. It is up to you how you actually get it to
      * the voters - email, or through your application's preferred messaging system.  The voter must then
      * decrypt and verify the ballot, append his or her vote (which is an int) and then re-encrypt it with the
      * Officer's public Lock
      *
      * @param paper
      */
     void notify(BigBinary paper, Officer officer, Signature signature);
}
