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
    //String username = TestValues.testUsernames[0];
    Map<Fingerprint, String> createdFingerprints=new HashMap<>();
    @Before
    public  void setup(){
        try {
            if (lockstore==null){lockstore=new MinigmaLockStore(TestValues.lockFile, true);}
            File keysDirectory = TestValues.keyDirectory;
            if (!keysDirectory.exists()) {
                keysDirectory.mkdirs();
                for (int i = 0; i < TestValues.testPassPhrases.length; i++) {
                    Lock lock = LockSmith.createLockset(TestValues.keyDirectory, lockstore,  TestValues.testPassPhrases[i].toCharArray(), Algorithms.RSA);
                    createdFingerprints.put(lock.getFingerprint(), TestValues.testPassPhrases[i]);
                }
            }

        }catch(Exception x){
            Exceptions.dump("CTSCSetup", x);
        }
    }
    @Test
    public void encryptionDecryptionTest(){
        setup();
        Key key=null;
        Lock lock=null;
        int i=1;
        for (Fingerprint fingerprint:createdFingerprints.keySet()) {
            try {
                //The Lock we are going to encrypt the data with)
                lock = lockstore.getLock(fingerprint);
                //The data we are going to encrypt
                byte[] clearbytes = MinigmaUtils.readFromBinaryFile(clearFile);
                byte[] cipherText = lock.lock(clearbytes);
                String shortDigest = Digester.shortDigest(cipherText);
                File cipherFile = new File(TestValues.cipherDirectory, shortDigest);
                MinigmaUtils.encodeToArmoredFile(cipherFile, cipherText);
                //that's it saved. Now to undo it.

                key = new Key(new File(TestValues.keyDirectory, fingerprint.toBase64String()));
                byte[] readCipherText = MinigmaUtils.readFromArmoredFile(cipherFile);
                byte[] decryptedBytes = key.unlockAsBytes(readCipherText, createdFingerprints.get(fingerprint).toCharArray());
                assertTrue(Arrays.equals(clearbytes, decryptedBytes));
                //MinigmaUtils.writeToBinaryFile(new File(clearDirectory, "decrypted"), decryptedBytes);
                System.out.println("Encryption/decryption test OK on iteration "+i);
            } catch (Exception e) {
                System.out.println("BZ "+e.getClass().getName()+"\n "+ e.getMessage());
                //System.out.println("caused by "+e.getCause().getClass().getName()+":"+e.getCause().getMessage());
                StackTraceElement[] stackTraceElements = e.getStackTrace();
                for (StackTraceElement stackTraceElement:stackTraceElements){
                    System.out.println(stackTraceElement.toString());
                }
            }
            i++;
        }
    }
}
