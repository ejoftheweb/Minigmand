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
        * SOFTWARE.
 * Created 9 Dec 2016
 * www.platosys.co.uk
 */
package uk.co.platosys.minigma;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import org.spongycastle.bcpg.CompressionAlgorithmTags;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.SignatureException;
import uk.co.platosys.minigma.exceptions.UnsupportedAlgorithmException;
import uk.co.platosys.minigma.utils.MinigmaUtils;
import uk.co.platosys.minigma.CryptoEngine;
import uk.co.platosys.minigma.Key;
import uk.co.platosys.minigma.Lock;
import uk.co.platosys.minigma.LockStore;

/**
 * Utility class with static methods for encrypting (locking)  and decrypting (unlocking)
 * @author edward

 */
public class Minigma {
    public static String TAG = "Minigma";
    public  static final String PROVIDER_NAME = "BC";
    public static final int  HASH_ALGORITHM = HashAlgorithmTags.SHA512;
    public  static final int  COMPRESS_ALGORITHM = CompressionAlgorithmTags.UNCOMPRESSED;
    public static final int  STRONG_ALGORITHM = SymmetricKeyAlgorithmTags.AES_256;
    public static final int WEAK_ALGORITHM=SymmetricKeyAlgorithmTags.TRIPLE_DES;
    public static final Provider PROVIDER = initialiseProvider();
    public static final String LOCK_DIRNAME="lock";
    public static final String KEY_DIRNAME="key";
    public static final String VERSION="v0.2.0.8.7/BC v1.58.0.0";
    public static final String LIBRARY_NAME="Minigma";

    /**
     * This takes an String and encrypts it with the given Lock
     * @param lock - the Lock with which to encrypt it;
     * @return
     * @throws MinigmaException
     */
    public static String lock(String clearString, Lock lock) throws MinigmaException{
        byte[] literalData=MinigmaUtils.toByteArray(clearString);
        byte[] compressedData = MinigmaUtils.compress(literalData);
        byte[] encryptedData= CryptoEngine.encrypt(compressedData, lock);
        return MinigmaUtils.encode(encryptedData);

    }

    /** This takes an EncryptedData String and returns  the cleartext
     * @return
     * @throws Exception
     */
    public static String unlock(String ciphertext, Key key, char[] passphrase) throws Exception {
        byte[] bytes = MinigmaUtils.decode(ciphertext);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return new String(CryptoEngine.decrypt(bais, key, passphrase), "UTF-8");
    }






    //Private methods



    protected static Provider initialiseProvider(){
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }



}


