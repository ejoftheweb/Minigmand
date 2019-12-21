/*/* (c) copyright 2018 Platosys
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
        * SOFTWARE.*
 * The LockSmith, as the name suggests, makes Locks and matching keys which it saves
 * as PGP ascii-armored keyring files in the keys directory.
 *
 * MIT Licensed
 *
 *
 *
 */
package uk.co.platosys.minigma;


import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.CompressionAlgorithmTags;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ElGamalParameterSpec;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPKeyPair;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.spongycastle.openpgp.operator.PGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.PGPDigestCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import uk.co.platosys.minigma.exceptions.DuplicateNameException;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.UnsupportedAlgorithmException;
import uk.co.platosys.minigma.utils.FileTools;
import uk.co.platosys.minigma.utils.MinigmaOutputStream;

/**
 * Key-pair - Lock&Key Pair generator
 * This is a key-pair generator - it has one static method which generates a Lock and a corresponding Key.
 * The (public) Lock is stored in the LockStore provided as an argument, and the private Key as a File in the
 * directory provided as a File argument.
 * Under the skin, in line with OpenPGP it generates three key pairs: a master key pair, which is used for certification, with
 * two subkeys, one for encryption, and one for signatures.
 * But they have the same passphrase.
 *
 *
 */

public class LockSmith {
    private static String PROVIDER="SC";



    /**
     * Generat a Lock & Key pair.
     * @param keyDirectory the directory in which the private Key is to be saved. This could be on a removable drive.
     * @param lockStore the LockStore in which the Lock(the public key) generated is to be stored.
     * @param userName
     * @param passPhrase
     * @return The key_id of the signing key.
     * @throws MinigmaException
     */
    public static Lock createLockset(
            File keyDirectory,
            LockStore lockStore,
            String userName,
            char[] passPhrase,
            int algorithm)
            throws MinigmaException,
            DuplicateNameException,
            UnsupportedAlgorithmException
    {
        String filename;
        File keyFile;
        String masterAlgorithm;
        String encryptionAlgorithm;
        String signingAlgorithm;
        int masterAlgorithmTag;
        int encryptionAlgorithmTag;
        int signingAlgorithmTag;

        //test that parameters have been set:
        if(algorithm==Algorithms.RSA){
            masterAlgorithm=Algorithms.RSAS;
            encryptionAlgorithm=Algorithms.RSAS;
            signingAlgorithm=Algorithms.RSAS;
            masterAlgorithmTag=PublicKeyAlgorithmTags.RSA_GENERAL;
            encryptionAlgorithmTag=PublicKeyAlgorithmTags.RSA_ENCRYPT;
            signingAlgorithmTag=PublicKeyAlgorithmTags.RSA_SIGN;
        }else{
            throw new UnsupportedAlgorithmException("Algorithm not supported by this implementation of Minigma");
        }
        if (keyDirectory == null) {
            throw new MinigmaException("Locksmith - key directory is null");
        }
        if (!keyDirectory.isDirectory()) {
            throw new MinigmaException("Locksmith: " + keyDirectory.toString() + " is not a directory");
        }
        if (!keyDirectory.canWrite()) {
            throw new MinigmaException("Locksmith: can't  write to " + keyDirectory.toString());
        }

        try {
            if (Security.getProvider(PROVIDER) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        } catch (Exception e) {
            throw new MinigmaException("Locksmith: problem adding security provider", e);
        }
        //
        KeyPairGenerator generator;
        KeyPair masterKeyPair;
        KeyPair signingKeyPair;
        KeyPair encryptionKeyPair;

        PGPKeyPair pgpMasterKeyPair;
        PGPKeyPair pgpSigningKeyPair;
        PGPKeyPair pgpEncryptionKeyPair;

        PGPKeyRingGenerator pgpKeyRingGenerator;
        PGPPublicKeyRing pgpPublicKeyRing;
        PGPSecretKeyRing pgpSecretKeyRing;
        Lock lock;
        Date creationDate = new Date();
        //The MasterKey
        try {
            generator = KeyPairGenerator.getInstance(masterAlgorithm, PROVIDER);
            generator.initialize(4096);
            masterKeyPair = generator.generateKeyPair();
            pgpMasterKeyPair=new JcaPGPKeyPair(masterAlgorithmTag, masterKeyPair, creationDate);

        } catch (Exception e) {
            throw new MinigmaException("Locksmith: failed to generate master key pair", e);
        }

        //The Signing subKey
        try {
            generator = KeyPairGenerator.getInstance(signingAlgorithm, PROVIDER);
            generator.initialize(2048);
            signingKeyPair = generator.generateKeyPair();
            pgpSigningKeyPair = new JcaPGPKeyPair(signingAlgorithmTag, signingKeyPair, creationDate);
        } catch (Exception e) {
            throw new MinigmaException("Locksmith: failed to generate signing key pair", e);
        }

        //The Encryption subKey
        try {
            generator = KeyPairGenerator.getInstance(encryptionAlgorithm, PROVIDER);
            generator.initialize(4096);
            encryptionKeyPair = generator.generateKeyPair();
            pgpEncryptionKeyPair=new JcaPGPKeyPair(encryptionAlgorithmTag, encryptionKeyPair,creationDate);
        } catch (Exception e) {
            throw new MinigmaException("Locksmith: failed to generate encryption key pair", e);
        }
        /*try {
            //the strong ElGamal key for encrypting
            generator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM, PROVIDER);
            AlgorithmParameterSpec elGamalParameters = new ElGamalParameterSpec(Algorithms.ELGAMAL_P, Algorithms.ELGAMAL_G);
            generator.initialize(elGamalParameters);
            encryptionKeyPair = generator.generateKeyPair();
        } catch (Exception e) {
            throw new MinigmaException("Locksmith: failed to generate elgamal key pair", e);
        }*/
        //

        try {
            filename = FileTools.removeFunnyCharacters(userName);
            keyFile = new File(keyDirectory, filename);
            if (keyFile.exists()) {
                throw new DuplicateNameException("keyfile with name " + keyFile.getName() + " already exists");
            }

        }catch (DuplicateNameException dnx){
            throw dnx;
        }catch(Exception exc){
            throw new MinigmaException("Locksmith: error setting up key files", exc);
        }
        PGPDigestCalculator pgpChecksumCalculator=null;
        PGPDigestCalculator pgpDigestCalculator = null;
        PGPContentSignerBuilder pgpContentSignerBuilder=null;
        PBESecretKeyEncryptor pbeSecretKeyEncryptor=null;
        try{
            pgpChecksumCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(Algorithms.STANDARDS_HASH);
            pgpDigestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(Algorithms.STRONG_HASH);
            pgpContentSignerBuilder = new JcaPGPContentSignerBuilder(signingAlgorithmTag, Algorithms.STRONG_HASH);
            pbeSecretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(Algorithms.SYMMETRIC_ALGORITHM, pgpDigestCalculator)
                    .setProvider(PROVIDER).build(passPhrase);
        }catch(Exception e){
            throw new MinigmaException("failed to initialise KRG components", e);
        }try{
        pgpKeyRingGenerator = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, //certification level
                pgpMasterKeyPair, //master key
                userName, // id
                pgpChecksumCalculator,//checksum calculator, uses SHA1
                null,//PGPSignatureSubpacketsVector hashed packets (null because a new Lock is unsigned)
                null,//PGPSignatureSubpacketsVector unhashed packets (null because a new Lock is unsigned)
                pgpContentSignerBuilder,//PGPContentSignerBuilder
                pbeSecretKeyEncryptor//PBESecretKeyEncryptor
        );

    }catch(PGPException e){
        //Policy files aren't needed with Java 9. But must set policy another way.
        throw new MinigmaException("Locksmith: failed to create PGP-keyring generator - have you installed the Sun unlimited strength policy files?", e);
    }try{
        pgpKeyRingGenerator.addSubKey(pgpSigningKeyPair);
        pgpKeyRingGenerator.addSubKey(pgpEncryptionKeyPair);
    }catch(Exception e){
        throw new MinigmaException("Locksmith: failed to add subkeys to the master ring", e);
    }try{
        //write the Key part to file as an OpenPGP secret keyring
        MinigmaOutputStream keyOut= new MinigmaOutputStream(new FileOutputStream(keyFile));
        pgpSecretKeyRing=pgpKeyRingGenerator.generateSecretKeyRing();
        pgpSecretKeyRing.encode(keyOut);
        keyOut.close();
    }catch(Exception e){
        throw new MinigmaException("Locksmith: failed to encode secret key output", e);
    }try{
        // create a minigma.Lock and add it to the LockStore
        pgpPublicKeyRing = pgpKeyRingGenerator.generatePublicKeyRing();
        lock = new Lock(pgpPublicKeyRing);
        lockStore.addLock(lock);
    }catch (Exception e){
        throw new MinigmaException("Locksmith: failed to create new Lock and add it to the LockStore",e);
    }

        return lock;

    }




}

