/*
 * Copyright Edward Barrow and Platosys.
 * This software is licensed under the Free Software Foundation's
General Public Licence, version 2 ("the GPL").
The full terms of the licence can be found online at http://www.fsf.org/

In brief, you are free to copy and to modify the code in any way you wish, but if you
publish the modified code you may only do so under the GPL, and (if asked) you must
 supply a copy of the source code alongside any compiled code.

Platosys software can also be licensed on negotiated terms if the GPL is inappropriate.
For further information about this, please contact software.licensing@platosys.co.uk
 */

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
import java.io.IOException;
import java.nio.charset.Charset;

import net.jpountz.xxhash.XXHash64;
import net.jpountz.xxhash.XXHashFactory;
import org.spongycastle.crypto.digests.KeccakDigest;
import org.spongycastle.crypto.digests.SHA3Digest;
import org.spongycastle.openpgp.PGPSignature;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 * a class with static methods for digesting elements, documents and
 * byte arrays.
 * @author edward
 */
public class Digester {
    private static String TAG ="Digester";

    public static String digest (String string) throws MinigmaException{
        return digest(string.getBytes(Charset.forName("UTF-8")));
    }
    /**Takes a byte array and returns a string which is
     * the Base64 encoded version the digest.
     * This uses SHA3-512 as the digest algorithm.
     *
     * */
    public static String digest (byte[] bytes) throws MinigmaException{
        try{
            KeccakDigest digest = new SHA3Digest(512);
            for(byte byt:bytes){
                digest.update(byt);
            }
            byte[] digested = new byte[digest.getDigestSize()];
            digest.doFinal(digested, 0);
            return(MinigmaUtils.encode(digested));
        }catch(Exception e){
            throw new MinigmaException("error making digest", e);
        }
    }

    /**
     * This returns a short String which is a non-cryptographic hash of
     * the supplied byte array. The short hashes so obtained are used as identifiers
     * and filenames for Signatures.
     * @param bytes
     * @return
     * @throws MinigmaException
     */
    public static String shortDigest (byte[] bytes) {
        try{ XXHashFactory xxHashFactory = XXHashFactory.fastestInstance();
            XXHash64 xxHash64 = xxHashFactory.hash64();
            long longHash = xxHash64.hash(bytes, 0, 0, 0);
            return(MinigmaUtils.encode(longHash));
        }catch(Exception e){
            Exceptions.dump(e);
            return null;
        }
    }
    public static String shortDigest (PGPSignature signature) {
        try {
            return shortDigest(signature.getEncoded());
        }catch(IOException iox){
            Exceptions.dump(iox);
            return null;
        }
    }

}

