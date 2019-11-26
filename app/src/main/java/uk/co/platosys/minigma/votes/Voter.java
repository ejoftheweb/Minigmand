package uk.co.platosys.minigma.votes;

import uk.co.platosys.minigma.BigBinary;
import uk.co.platosys.minigma.Lock;

public interface Voter {
     Lock getLock();
     void notify(BigBinary paper);
}
