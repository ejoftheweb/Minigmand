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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;

/**This is an implementation of LockStore that uses public keyservers
 * as the backing store, with which it communicates using the HKP protocol
 * based on http.
 *
 */

public class HKPLockStore implements LockStore {
    private URL url;

    public HKPLockStore(URL url){
        this.url=url;
    }


    @Override
    public boolean addLock(Lock lock) {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");
            return false;
        }catch(Exception x){
            return false;
        }
    }

    /** This method always returns false. It is not practicable (or for that matter usually ever desirable) to remove a public key from
     * a public keyserver.
     * @param lockID
     * @return always false*/
    @Override
    public boolean removeLock(byte[] lockID) {
        return false;
    }

    @Override
    public Lock getLock(byte[] keyID) {
        return null;
    }

    @Override
    public Iterator<Lock> iterator() throws MinigmaException {
        return null;
    }

    @Override
    public Lock getLock(String userID) throws MinigmaException {
        return null;
    }

    @Override
    public boolean contains(String userID) {
        return false;
    }

    @Override
    public long getStoreId() {
        return 0;
    }

    @Override
    public String getUserID(byte[] keyID) {
        return null;
    }

    @Override
    public String getUserID(long keyID) {
        return null;
    }

    @Override
    public int getCount() {
        return 0;
    }
}

