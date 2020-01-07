package uk.co.platosys.minigma.votes;

import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

/**Abstract class representing a Set of Voters.  Applications will need to
 * develop their own implementation of the sendVotes() method.
 *
 */
public interface Electorate extends Set<Voter> {
    /**
     *  Concrete implementations need to actually send the votes to the voters. Something like
     *  for(Voter elector:electors){
     *      User user = (User) elector;
     *      String email = user.getEmail();
     *      mailto(email, elector.getPaper(), elector.getSignature();
     *  }
     * @return
     */
    boolean  sendVotes();

}