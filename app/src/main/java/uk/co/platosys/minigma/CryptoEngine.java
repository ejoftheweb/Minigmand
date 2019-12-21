
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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.*;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.spongycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.spongycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.spongycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import uk.co.platosys.minigma.Key;
import uk.co.platosys.minigma.Lock;
import uk.co.platosys.minigma.Minigma;
import uk.co.platosys.minigma.exceptions.BadPassphraseException;
import uk.co.platosys.minigma.exceptions.DecryptionException;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.MinigmaOtherException;
import uk.co.platosys.minigma.exceptions.NoDecryptionKeyException;
import uk.co.platosys.minigma.utils.Kidney;
import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 * this  class holds the static decrypt and encrypt methods
 *
 * @author edward
 */
public  class CryptoEngine {
    private static String TAG ="CryptoEngine";

    /**
     *  Decrypts an InputStream to a byte array
     *
     * @param inputStream
     * @param key
     * @param passphrase
     * @return
     * @throws Exception
     */

    public static byte[] decrypt(InputStream inputStream, Key key, char[] passphrase)
            throws MinigmaOtherException,
            BadPassphraseException
            {
        InputStream decoderStream;
        PGPObjectFactory pgpObjectFactory=null;
        PGPEncryptedDataList pgpEncryptedDataList = null;
        try {
            decoderStream = PGPUtil.getDecoderStream(inputStream);
            pgpObjectFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
            boolean moreObjects=true;
            while (moreObjects) {
                Object object = pgpObjectFactory.nextObject();
                if (object == null) {
                    moreObjects = false;
                }
                if (object instanceof PGPEncryptedDataList) {
                    pgpEncryptedDataList = (PGPEncryptedDataList) object;
                    PGPCompressedData compressedData = decrypt(pgpEncryptedDataList, key, passphrase);
                    return decompress(compressedData);
                } else {
                    System.out.println(object.getClass().getName());
                }
            }
            throw new MinigmaException("couldn't find encrypted data list");
        }catch(BadPassphraseException bpe){
            throw bpe;
        } catch(Exception e){
            Exceptions.dump(e);
            throw new MinigmaOtherException("error reading encrypted data list", e);
        }
    }

    /**
     * An encryptedDataList will contain one or more blocks of encrypted data, usually the same literal data encrypted
     * to one or more public keys. Typically, the provided Key will only be able to unlock one of them.
     * @param pgpEncryptedDataList
     * @param key
     * @param passphrase
     * @return
     * @throws MinigmaException
     * @throws DecryptionException
     */
    private static PGPCompressedData decrypt(PGPEncryptedDataList pgpEncryptedDataList, Key key, char[] passphrase) throws MinigmaOtherException, BadPassphraseException, DecryptionException {
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = null;
        try {
            Iterator<PGPPublicKeyEncryptedData> it = pgpEncryptedDataList.getEncryptedDataObjects();
            JcePBESecretKeyDecryptorBuilder keyDecryptorBuilder = new JcePBESecretKeyDecryptorBuilder();
            keyDecryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            int size = pgpEncryptedDataList.size();
            int count = 0;
            while (it.hasNext() && privateKey == null) {
                pgpPublicKeyEncryptedData = it.next();
                count++;
                //System.out.println();
                long keyID = pgpPublicKeyEncryptedData.getKeyID();
                //System.out.println("EncryptedDataBlock was encrypted with keyID "+Kidney.toString(keyID));
                try {
                    PGPSecretKey secretKey = key.getDecryptionKey(keyID);
                    if (secretKey.getKeyID() == keyID) {
                        try {
                            privateKey = key.getDecryptionKey(keyID).extractPrivateKey(keyDecryptorBuilder.build(passphrase));
                            //System.out.println("Key match for "+Kidney.toString(keyID));
                        } catch (PGPException pgpException) {
                            throw new BadPassphraseException("bad passphrase", pgpException);

                        }
                    }
                } catch (BadPassphraseException bpe) {
                    throw bpe;
                } catch
                (NoDecryptionKeyException ndke) {
                    //System.out.println("no decryption key available for keyID "+Kidney.toString(keyID));
                    //we don't need to worry about this exception here.
                } catch (Exception x) {
                    System.out.println("oops exception in decrypt while loop");
                    Exceptions.dump(x);
                    throw new MinigmaException("CryptoEngine: getEncryptedDataObjects - unexpected exception", x);
                }
            }
            if (privateKey == null) {
                //System.out.println("Done "+ count + "keys of "+size+" altogether, still no private key");
                throw new DecryptionException("CryptoEngine: decryption key doesn't fit any of the locks");
            }
        }catch(BadPassphraseException bpe){
            throw bpe;
        }catch (DecryptionException dx) { //don't think this is ever thrown here
            Exceptions.dump(dx);
            throw dx;
        }catch (Exception e) {
            Exceptions.dump(e);
            throw new MinigmaOtherException("A problem arose during decryption", e);
        }
        //so we now have an encrypted data object and a key that fits it...
        try {
            PublicKeyDataDecryptorFactory dataDecryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
            InputStream decryptedStream = pgpPublicKeyEncryptedData.getDataStream(dataDecryptorFactory);
            JcaPGPObjectFactory compressedFactory = new JcaPGPObjectFactory(decryptedStream);
            return (PGPCompressedData) compressedFactory.nextObject();

        } catch (Exception e) {
            Exceptions.dump(e);
            throw new MinigmaOtherException("Minigma-unLock() 3: error reading encrypted data stream", e);
        }
    }

    private static byte[] decompress (PGPCompressedData clearCompressedData) throws  MinigmaOtherException{
        PGPLiteralData literalData=null;
        try {
            InputStream inputStream = clearCompressedData.getDataStream();
            JcaPGPObjectFactory decompressedFactory = new JcaPGPObjectFactory(inputStream);
            boolean moreObjects=true;
            while ((literalData==null)&&(moreObjects)) {
                Object decompressedObject = decompressedFactory.nextObject();
                if (decompressedObject==null){moreObjects=false;}
                if (decompressedObject instanceof PGPLiteralData) {
                    literalData = (PGPLiteralData) decompressedObject;
                }
            }
            return MinigmaUtils.readStream(literalData.getDataStream());
        }catch(Exception e){
            Exceptions.dump(e);
            throw new MinigmaOtherException( "Minigma-unLock() 4: error getting decompressed object", e );
        }
    }

    /**
     * Returns a byte array of encrypted data. The resultant binary data must be base64 encoded
     * for transport by text systems such as xml.
     * @param compressedData
     * @param lock
     * @return
     * @throws MinigmaException
     */
    @SuppressWarnings("resource")
    public static byte[] encrypt (byte[] compressedData, Lock lock) throws MinigmaException{
        Minigma.initialiseProvider();
        PGPEncryptedDataGenerator encryptedDataGenerator=configureGenerator(Algorithms.SYMMETRIC_ALGORITHM,lock);
        ByteArrayOutputStream encryptedByteStream = new ByteArrayOutputStream();
        OutputStream outputStream;

        try {
            outputStream = encryptedDataGenerator.open(encryptedByteStream, compressedData.length);
        }catch(PGPException pgpe) {
            Exceptions.dump(pgpe);
            throw new MinigmaException("Error generating cypher: have you installed the unlimited strength policy files?", pgpe);
        }catch(Exception e){
            Exceptions.dump(e);
            throw new MinigmaException("Error generating cypher: refer to stack trace for details", e);

        }try{
            outputStream.write(compressedData);
            outputStream.flush();
            outputStream.close();
            byte[] encryptedBytes = encryptedByteStream.toByteArray();
            encryptedDataGenerator.close();
            return encryptedBytes;
        }catch(Exception e){
            Exceptions.dump(e);
            throw new MinigmaException("Cryptoengine-encrypt: ", e);
        }
    }

    private  static PGPEncryptedDataGenerator configureGenerator(int algorithm, Lock lock) throws MinigmaException {
        PGPEncryptedDataGenerator encryptedDataGenerator;

        try{
            JcePGPDataEncryptorBuilder pgpDataEncryptorBuilder = new JcePGPDataEncryptorBuilder(algorithm);
            pgpDataEncryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            encryptedDataGenerator = new PGPEncryptedDataGenerator(pgpDataEncryptorBuilder);
            Iterator<PGPPublicKeyRing> it = lock.getPGPPublicKeyRingIterator();
            if (!it.hasNext()){
                throw new MinigmaException("Empty Lock: "+lock.toString());
            }
            while (it.hasNext()){
                PGPPublicKeyRing keyRing = it.next();
                Iterator<PGPPublicKey> publicKeyIterator = keyRing.getPublicKeys();
                while(publicKeyIterator.hasNext()){
                    PGPPublicKey pgpPublicKey = publicKeyIterator.next();
                    if(pgpPublicKey.isEncryptionKey()){
                        PGPKeyEncryptionMethodGenerator methodGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey);
                        encryptedDataGenerator.addMethod(methodGenerator);
                        System.out.println("added encryption method for keyID "+ Kidney.toString(pgpPublicKey.getKeyID()));
                    }
                }
            }
            return encryptedDataGenerator;
        }catch(Exception e){
            throw new MinigmaException("Minigma-encrypt: error configuring generator",e);
        }
    }
}

