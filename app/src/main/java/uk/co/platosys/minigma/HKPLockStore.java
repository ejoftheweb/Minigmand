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
import android.util.Log;

import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;

import static java.net.HttpURLConnection.HTTP_ACCEPTED;
import static java.net.HttpURLConnection.HTTP_NOT_FOUND;
import static java.net.HttpURLConnection.HTTP_OK;

/**This is an implementation of LockStore that uses public keyservers
 * as the backing store, with which it communicates using the HKP protocol
 * based on http.
 *
 */

public class HKPLockStore implements LockStore {

private String host;
private int port=11371; //this is the the default HKP port number
public static final String PROTOCOL="http:";
public static final String GET_FILE_PART="pks/lookup";
public static final String POST_FILE_PART="pks/add";
public static final String ARMORED_PKEY_OPEN="-----BEGIN PGP PUBLIC KEY BLOCK-----";
public static final String ARMORED_PKEY_CLOSE="-----END PGP PUBLIC KEY BLOCK-----";
private String TAG = "HKPLockstore";

    /**
     *  Create an instance of the HKPLockStore by specifying a hostname and a port number to the constructor.
     *
     * @param host

     */
    public HKPLockStore(String host){
        this.host=host;

        //should  constructor verify host's existence? How?

    }


    @Override
    public boolean addLock(Lock lock) {
        try {
            URL url = new URL(PROTOCOL, host, port, POST_FILE_PART);

            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");
            httpURLConnection.setDoOutput(true); //changes the default method to POST.
            httpURLConnection.addRequestProperty("op","post");
            httpURLConnection.addRequestProperty("options", "mr");
            OutputStream outputStream = new BufferedOutputStream( httpURLConnection.getOutputStream());
            outputStream.write(("keytext = ").getBytes());
            outputStream.write(lock.toArmoredString().getBytes());
            outputStream.flush();
            outputStream.close();
            int response = httpURLConnection.getResponseCode();
            switch (response){
                case HTTP_OK:
                    return true;
                case HTTP_ACCEPTED:
                    return true;
                default:
                    handleError(response);

            }

            return false;
        }catch(Exception x){
            return false;
        }
    }

    /** This method always returns false. It is not practicable (or for that matter usually ever desirable) to remove a public key from
     * a public keyserver.
     * @param fingerprint
     * @return always false*/
    @Override
    public boolean removeLock(Fingerprint fingerprint) {
        return false;
    }

    /**This method retrieves a Lock from the server given its keyID/fingerprint*/
    @Override
    public Lock getLock(Fingerprint fingerprint) {
        byte[] keyID = fingerprint.getFingerprintbytes();

        try {
            URL url = new URL(PROTOCOL, host, port, GET_FILE_PART);

            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.addRequestProperty("op","get");
            httpURLConnection.addRequestProperty("options", "mr");

            httpURLConnection.addRequestProperty("search", Kidney.toString(keyID));
            Log.d(TAG, url.getQuery());
            int responseCode = httpURLConnection.getResponseCode();
            switch (responseCode){
                case HTTP_OK:
                    return extractLock(httpURLConnection);
                //break;
                case HTTP_NOT_FOUND:
                    break;

                default:

            }
            return null;
        }catch(Exception x){
            Exceptions.dump(x);
            return null;
        }
    }

    @Override
    public Iterator<Lock> iterator() throws MinigmaException {
        return null;
    }

    /**This method retrieves a Lock from the server given a userID*/
    @Override
    public Lock getLock(String userID) throws MinigmaException {
        try {
            URL url = new URL(PROTOCOL, host, port, GET_FILE_PART);
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.addRequestProperty("op","get");
            httpURLConnection.addRequestProperty("options", "mr");
            httpURLConnection.addRequestProperty("search", userID);
            int responseCode = httpURLConnection.getResponseCode();
            switch (responseCode){
                case HTTP_OK:
                    return extractLock(httpURLConnection);
                    //break;
                case HTTP_NOT_FOUND:
                    break;
                default:

            }
        }catch (IOException iox){

        }
        return null;
    }

    private Lock extractLock(HttpURLConnection httpURLConnection){
        try {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();
            StringBuffer pgpKeysBlock = new StringBuffer();
            boolean pkey = false;
            while ((inputLine = bufferedReader.readLine()) != null) {
                if (inputLine.contains(ARMORED_PKEY_OPEN)){pkey=true;}
                if (pkey){pgpKeysBlock.append(inputLine);}
                response.append(inputLine);
                if (inputLine.contains(ARMORED_PKEY_CLOSE)){pkey=false;}
            }
            bufferedReader.close();
            Lock lock = new Lock(pgpKeysBlock.toString());
            return lock;
        }catch (IOException iox){
            //TODO
            Exceptions.dump(iox);
        }catch (MinigmaException mx) {
            //TODO
            Exceptions.dump(mx);
        }
        return null;
    }
    @Override
    public boolean contains(String userID) {
        try {
            return (getLock(userID) instanceof Lock);
        }catch (Exception x){
            return false;
        }
    }

    @Override
    public long getStoreId() {
        return 0;
    }

    @Override
    public String getUserID(Fingerprint fingerprint) {
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

    public void setPort(int port){
        this.port=port;
    }
    private void handleError(int response){
        Log.d(TAG, "HTTP error code:"+response);
    }
}

