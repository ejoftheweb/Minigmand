package uk.co.platosys.minigma;

//import android.support.annotation.NonNull;

import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;

import java.math.BigInteger;
import java.text.ParseException;

import uk.co.platosys.minigma.utils.MinigmaUtils;

/**In crypto we use big binary numbers a lot. Often, the java.math class BigInteger will suffice,
 * or we can just handle the underlying byte arrays. BigBinary is a wrapper for a byte[] and includes
 * methods for instantiating from, and returning the underlying number as, a Base64 String which is often the most
 * practical way of handling it, now that the ubiquity of UTF-8 has removed most of the headache of competing
 * incompatible character sets.
 *
 * BigBinary was introduced in Minigma v0.2, replacing the earlier use of Strings as digests etc. There's
 * thus less need for Base64 coding and decoding under the hood - because BigBinary is a byte array in an Object -
 * and it avoids any confusion with cleartext semantic Strings.
 *
 */
public class BigBinary implements Comparable{
    private byte[] bytes;
    public BigBinary (String string)throws ParseException {
        this.bytes= MinigmaUtils.decode(string);
    }
    public BigBinary(byte[] bytes){
        this.bytes=bytes;
    }
    @Override
    public String toString(){
        return MinigmaUtils.encode(bytes, true);
    }
    public byte[] toByteArray(){
        return bytes;
    }
    public int getBitlength(){
        return bytes.length*8;
    }

    public BigInteger toBigInteger() {return new BigInteger(bytes);}
    //Append methods
    /**
     * Appends the given integer to this BigBinary. Note this is not the same as addition, it is basically
     *  multiplying by 2^32 and then adding.
     * @param annex
     * @return this BigBinary with the annex appended.
     */
    public BigBinary append(int annex){
        byte[]addbytes = Ints.toByteArray(annex);
        return append(addbytes);
    }

    public BigBinary append (long annex){
        byte[] addbytes = Longs.toByteArray(annex);
        return append(addbytes);
    }

    public BigBinary append(byte[] annex){
        byte[] newArray = new byte[bytes.length+annex.length];
        int a=0;
        for (int i=0; i<bytes.length; i++){
            newArray[a]=bytes[i];
            a++;
        }
        for (int i=0; i<annex.length; i++){
            newArray[a]=annex[i];
            a++;
        }
        this.bytes=newArray;
        return this;
    }
    //Detach methods
    /** The detach methods are the inverses of the append methods
     * This method detaches a byte array of length length from the
     * underlying byte array.
     */
    public byte[] detach(int length) throws ArrayIndexOutOfBoundsException {
        if(length>bytes.length){throw new ArrayIndexOutOfBoundsException("attempting to detach too much");}

        byte[] detached = new byte[length];
        byte[] remains = new byte[bytes.length-length];
        for (int i=0; i<remains.length; i++){
            remains[i]=bytes[i];
        }
        for (int i=remains.length; i<bytes.length; i++){
            detached[i]=bytes[i];
        }
        this.bytes=remains;
        return detached;
    }
    public long detachLong() throws ArrayIndexOutOfBoundsException {
        byte[] detached = detach( Longs.BYTES);
        return Longs.fromByteArray(detached);
    }
    public int detachInt() throws ArrayIndexOutOfBoundsException {
        byte[] detached = detach(Ints.BYTES);
        return Ints.fromByteArray(detached);
    }
    @Override
    public boolean equals (Object object){
        if (object instanceof BigBinary){
            BigBinary bigBinary = (BigBinary) object;
            byte[] theirs = bigBinary.toByteArray();
            if (theirs.length != bytes.length) {return false;}
            for (int i=0; i<bytes.length; i++){
                if (bytes[i]!=theirs[i]){return false;}
            }
            return true;
        }else{
            return false;
        }
    }
    @Override
    public int compareTo( Object object) {
        if (object instanceof BigBinary){
            BigBinary bigBinary = (BigBinary) object;
            byte[] theirs = bigBinary.toByteArray();
            if (theirs.length != bytes.length) {
                //this behaviour isn't quite right. But it will do for now.
                //TODO fixit.
                throw new ClassCastException("comparing unequal bitlength BigBinaries");
            }
            for (int i=0; i<bytes.length; i++){
                if (bytes[i]>theirs[i]) {return 1;}
                if (bytes[i]<theirs[i]) {return -1;}

            }
            return 0;//we've gone through the whole array and they're all equal.
        }else{
            throw new ClassCastException();
        }
    }
}
