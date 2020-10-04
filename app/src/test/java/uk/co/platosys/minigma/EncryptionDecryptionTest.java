package uk.co.platosys.minigma;

import org.junit.Before;
import org.junit.Test;

import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.utils.MinigmaUtils;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;
import static uk.co.platosys.minigma.TestValues.clearFile;

public class EncryptionDecryptionTest {
    LockStore lockstore;
    Map<String,String> fingerprints = new HashMap<>();
    @Before
    public  void setup(){
        try {
            if (lockstore==null){lockstore=new MinigmaLockStore(TestValues.lockFile, true);}

            File keyFile = TestValues.keyDirectory;
            if (!keyFile.exists()) {
                keyFile.mkdirs();
                for (int i = 0; i < TestValues.testPassPhrases.length; i++) {
                    Lock lock = LockSmith.createLockset(TestValues.keyDirectory, lockstore, TestValues.testPassPhrases[i].toCharArray(), Algorithms.RSA);
                    fingerprints.put(lock.getFingerprint().toBase64String(), TestValues.testPassPhrases[i]);
                }
            }

        }catch(Exception x){
            Exceptions.dump("CTSCSetup", x);
        }
    }
    @Test
    public void encryptionDecryptionTest(){
        Key key=null;
        Lock lock=null;
        for (String fingerprint:fingerprints.keySet()) {
            try {
                //The Lock we are going to encrypt the data with)
                lock = lockstore.getLock(new Fingerprint(fingerprint));

                //The data we are going to encrypt
                byte[] clearbytes = MinigmaUtils.readFromBinaryFile(clearFile);
                byte[] cipherText = lock.lock(clearbytes);
                String shortDigest = Digester.shortDigest(cipherText);
                File cipherFile = new File(TestValues.cipherDirectory, shortDigest);
                MinigmaUtils.encodeToArmoredFile(cipherFile, cipherText);
                //that's it saved. Now to undo it.

                key = new Key(new File(TestValues.keyDirectory,fingerprint));
                byte[] readCipherText = MinigmaUtils.readFromArmoredFile(cipherFile);
                byte[] decryptedBytes = key.unlockAsBytes(readCipherText,fingerprints.get(fingerprint).toCharArray());
                assertTrue(Arrays.equals(clearbytes, decryptedBytes));
                //MinigmaUtils.writeToBinaryFile(new File(clearDirectory, "decrypted"), decryptedBytes);
                //System.out.println("Encryption/decryption test OK on iteration "+i);
            } catch (Exception e) {
                System.out.println("BZ "+e.getClass().getName()+"\n "+ e.getMessage());
                //System.out.println("caused by "+e.getCause().getClass().getName()+":"+e.getCause().getMessage());
                StackTraceElement[] stackTraceElements = e.getStackTrace();
                for (StackTraceElement stackTraceElement:stackTraceElements){
                    System.out.println(stackTraceElement.toString());
                }
            }
        }
    }
}
