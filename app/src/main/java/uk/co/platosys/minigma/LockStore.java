package uk.co.platosys.minigma;
/* (c) copyright 2018 Platosys
        * MIT Licence
        * Permission is hereby granted, free of charge, to any person obtaining a copy
        * of this software and associated documentation files (the "Software"), to deal
        * in the Software without restriction, including without limitation the rights
        * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        * copies of the Software, and to permit persons to whom the Software is
        * furnished to do so, subject to the following conditions:
        *
        *The above copyright notice and this permission notice shall be included in all
        * copies or substantial portions of the Software.
        *
        * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        * SOFTWARE.*/
import uk.co.platosys.minigma.exceptions.MinigmaException;

import java.util.Iterator;

/**
 * This interface defines how Locks are stored. Minigma provides one implementation, MinigmaLockStore,
 * which uses PGPPublicKeyRings as a storage mechanism.
 *
 * Minigma does not use OpenPGP KeyIDs, but only fingerprints (the 160-bit timestamped hash of the public key)
 * OpenPGP short (32-bit) KeyIDs are broadly deprecated as it is now trivial to generate collisions, that is,
 * keys that have the same short keyID. Long (64-bit) keyIDs are much more secure, but collisions are theoretically
 * possible. Using the 160-bit fingerprint is less convenient if this is ever to be done humanly but Minigma is all about
 * doing this by machine.
 *
 */
public interface LockStore {
    /**
     * Adds a Lock to a Lockstore. If the Lockstore already contains a Lock with that id, it
     * is replaced (typically because the Lock's certification has changed).
     *
     * @param lock
     * @return
     */
    boolean addLock(Lock lock);

    boolean removeLock(byte[] lockID);

    Lock getLock(byte[] keyID);

    Iterator<Lock> iterator() throws MinigmaException;

    Lock getLock(String userID)throws MinigmaException;

    boolean contains(String userID);

    long getStoreId();

    String getUserID(byte[] keyID);
    String getUserID(long keyID);

    int getCount();//returns the number of keys held by  this Lockstore
}
