package uk.co.platosys.minigma.votes;

import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

/**Abstract class representing a Set of Voters.  Applications will need to
 * develop their own implementation of the sendVotes() method.
 *
 */
public abstract class Electorate implements Set<Voter> {
    /**
     *  Concrete implementations need to actually send the votes to the voters. Something like
     *  for(Voter elector:electors){
     *      User user = (User) elector;
     *      String email = user.getEmail();
     *      mailto(email, elector.getPaper(), elector.getSignature();
     *  }
     * @return
     */
    public abstract boolean  sendVotes();
    protected Set<Voter> electors;
    public Electorate(Set<Voter> electors){
        this.electors=electors;
    }
    @Override
    public int size() {
        return electors.size();
    }

    @Override
    public boolean isEmpty() {
        return electors.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return electors.contains(o);
    }

    @Override
    public Iterator<Voter> iterator() {
        return electors.iterator();
    }

    @Override
    public Object[] toArray() {return electors.toArray();
    }

    @Override
    public <T> T[] toArray(T[] ts) {
        return null;
    }

    @Override
    public boolean add(Voter voter) {
        return electors.add(voter);
    }

    @Override
    public boolean remove(Object o) {
        return electors.remove(o);
    }

    @Override
    public boolean containsAll(Collection<?> collection) {
        return electors.contains(collection);
    }

    @Override
    public boolean addAll(Collection<? extends Voter> collection) {return electors.addAll(collection);}

    @Override
    public boolean retainAll(Collection<?> collection) { return electors.retainAll(collection);}

    @Override
    public boolean removeAll(Collection<?> collection) {
        return electors.removeAll(collection);
    }

    @Override
    public void clear() {
        electors.clear();
    }
}