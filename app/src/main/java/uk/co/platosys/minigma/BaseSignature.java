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
import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.sig.NotationData;
import org.spongycastle.openpgp.*;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.MinigmaOutputStream;
import uk.co.platosys.minigma.utils.MinigmaUtils;

import java.io.*;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Abstract base class wrapping PGPSignature objects
 */
public abstract class BaseSignature {
    protected PGPSignature pgpSignature;
    protected String shortDigest;


    /**
     * Instantiates a Minigma Signature object from a BouncyCastle PGPSignature object
     * @param pgpSignature
     */
    protected BaseSignature (PGPSignature pgpSignature){
        this.pgpSignature=pgpSignature;
        this.shortDigest=Digester.shortDigest(pgpSignature);

    }

    /**Instantiates a Minigma Signature object given a suitably-encoded String
     * @param string a Base64-encoded String
     * @throws ParseException if the supplied String contains wrong characters.
     */
    protected BaseSignature (String string) throws ParseException {
        this (new BigBinary(string));
    }

    /**Instantiates a Minigma Signature object given a BigBinary object.
     * @param bigBinary the signature as a BigBinary object.
     */
    protected BaseSignature (BigBinary bigBinary){
        this(new ByteArrayInputStream(bigBinary.toByteArray()));

    }
    protected BaseSignature (InputStream inputStream){
        PGPSignatureList signatureList;
        try {
            ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream);
            JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(armoredInputStream));
            Object object = jcaPGPObjectFactory.nextObject();
            if (object instanceof PGPCompressedData) {
                PGPCompressedData pgpCompressedData = (PGPCompressedData) object;
                jcaPGPObjectFactory = new JcaPGPObjectFactory(pgpCompressedData.getDataStream());
                Object object2 = jcaPGPObjectFactory.nextObject();
                if (object2 instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) object2;
                } else {
                    throw new MinigmaException("unexpected object type found in compressed data signature stream");
                }
            } else if (object instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) object;
            } else {
                throw new MinigmaException("unexpected object type found in uncompressed signature stream");
            }
            this.pgpSignature=signatureList.get(0);
            this.shortDigest=Digester.shortDigest(pgpSignature);
        }catch(Exception x){

        }
    }
    /**
     * Returns the Signature as a String. The String representations don't have PGP Ascii Armor so aren't fully interoperable,
     * if you need Ascii Armor, use the following method with armored=true.
     * @return
     */
    public String encodeToString(){return encodeToString(false);}

    public String encodeToString(boolean armored){
        return MinigmaUtils.encode(encodeToBytes(armored));
    }
    protected byte[] encodeToBytes (boolean armored){
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            encodeToStream(byteArrayOutputStream, armored);
        }catch(Exception x){}
        byte[] signatureBytes=byteArrayOutputStream.toByteArray();
        return signatureBytes;
    }
    protected byte[] getBytes(){
        return encodeToBytes(false);
    }

    protected BigBinary getBigBinary() {return new BigBinary(encodeToBytes(false));}

    /**
     * Writes the signature to the given output stream, with or without PGP Ascii Armor headers/footers.
     * Use armored=false if interoperability isn't a concern.
     *
     * @param outputStream
     * @param armored
     * @throws IOException
     */
    public void encodeToStream(OutputStream outputStream, boolean armored) throws IOException{
        if(armored){
            encodeToStream(outputStream);
        }else{
            pgpSignature.encode(outputStream);
            outputStream.flush();
            outputStream.close();
        }
    }

    /**
     * Writes the signature to the given output stream in PGP AsciiArmored format. This maximises interoperability with
     * other OpenPGP implementations.
     * @param outputStream
     * @throws IOException
     */
    public void encodeToStream(OutputStream outputStream) throws IOException{
        ArmoredOutputStream armoredOutputStream = new MinigmaOutputStream(outputStream);
        pgpSignature.encode(armoredOutputStream);
        armoredOutputStream.flush();
        armoredOutputStream.close();
    }

    /**
     * Writes the signature to the given file in PGP Ascii Armored format. This maximises interoperability with
     * other OpenPGP implementations.
     * @param file
     * @throws IOException
     */
    public void encodeToFile(File file) throws  IOException{
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        encodeToStream(fileOutputStream);
        fileOutputStream.flush();
        fileOutputStream.close();
    }

    /**
     * The short digest is a Minigma extension to the OpenPGP standard and returns
     * a non-cryptographic short digest which can be used, for example, as a filename for the signature
     * itself. The short digest uses a different fast hashing algorithm. It's not a digest of
     * the material being signed but of the signature itself.  It's not easily reversible, but it's not
     * demonstrably hard either, nor is it guaranteed to be collision-free, so it should only be used where
     * the consequences of either a collision or of someone managing to deduce the original from the digest
     * are manageable.
     * @return a short digest of the Signature object.
     */
    public String getShortDigest(){
        return shortDigest;
    }

    /**
     * Returns the ID of the key that signed this signature, as a long. Note that this is a 64-bit keyID, and not a 160-bit fingerprint.
     * Bear in mind that collisions (an ID identifying a different key) are somewhat less unlikely with
     * 64-bit IDs, which is why current best PGP practice is to use fingerprints rather than keyIDs. But what is likely
     * to happen? You get the keyID, use it to look up a corresponding Lock (public key), and if it's the wrong
     * one, the signature won't verify. Don't associate an actual person with a signature until it is properly
     * verified.
     * @return
     */
    public long getKeyID(){
        return pgpSignature.getKeyID();
    }


    @Override
    public boolean equals(Object object){
        if (object instanceof BaseSignature){
            BaseSignature baseSignature = (BaseSignature) object;
            return Arrays.equals(getBytes(),baseSignature.getBytes());
        }else{
            return false;
        }
     }

    /**OpenPGP allows Signatures to carry NotationData, which is an extensible, user-defined
     * vehicle for attaching additional information to a signature. Minigma specifically uses
     * name-value pairs for this (the mechanism also allows for binary NotationData, which is
     * not currently supported under Minigma).
     * @return List of Notation objects.
     */
    public List<Notation> getNotations(){
        List<Notation> notations = new ArrayList<>();
        PGPSignatureSubpacketVector notationVector = pgpSignature.getHashedSubPackets();
        NotationData[] notationData = notationVector.getNotationDataOccurrences();
        for(NotationData notationD:notationData){
            Notation notation = new Notation(notationD.getNotationName(), notationD.getNotationValue());
            notation.setCritical(notationD.isCritical());
            notation.setHumanReadable(notationD.isHumanReadable());
            notations.add(notation);
        }
        return notations;
    }
    protected PGPSignature getPgpSignature(){
        return pgpSignature;
    }
    public int getHashAlgorithm(){
            return pgpSignature.getHashAlgorithm();
    }
    public int getKeyAlgorithm(){
            return pgpSignature.getKeyAlgorithm();
    }
    protected  int getSignatureType(){
        return pgpSignature.getSignatureType();
    }
}
