package uk.co.platosys.minigma.exceptions;

import java.lang.Exception;


/**Exception thrown by LockStore if a requested Lock is
 * not found.
 *
 */
public class LockNotFoundException extends Exception {
    public LockNotFoundException(String msg){
        super(msg);
    }

}
