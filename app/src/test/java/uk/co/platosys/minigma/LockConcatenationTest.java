package uk.co.platosys.minigma;

import org.junit.Before;
import org.junit.Test;
import uk.co.platosys.minigma.exceptions.DuplicateNameException;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.FileTools;
import uk.co.platosys.minigma.utils.Kidney;
import uk.co.platosys.minigma.utils.MinigmaUtils;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class LockConcatenationTest {

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
    public void lockConcatenationTest(){
        try {
            for(Fingerprint fingerprint:createdFingerprints.keySet()){
                //Create a concatenated Lock
                Lock lock = lockstore.getLock(fingerprint);
                for (Fingerprint fingerprint1:createdFingerprints.keySet()) {
                    Lock newLock = lockstore.getLock(fingerprint1);
                    long newLockID = newLock.getPGPPublicKeyRingIterator().next().getPublicKey().getKeyID();
                    assertTrue(newLockID==fingerprint1.getKeyID());
                    lock = lock.addLock(newLock, false);
                }
                byte[] clearbytes = MinigmaUtils.readFromBinaryFile(TestValues.clearFile);
                byte[] cipherText = lock.lock(clearbytes);
                String shortDigest = Digester.shortDigest(cipherText);
                File cipherFile = new File(TestValues.cipherDirectory, shortDigest);
                MinigmaUtils.encodeToArmoredFile(cipherFile, cipherText);

                int i=1;
                for (Fingerprint fingerprint1:createdFingerprints.keySet()) {
                    Key key = new Key(new File(TestValues.keyDirectory, fingerprint1.toBase64String()));
                    byte[] readCipherText = MinigmaUtils.readFromArmoredFile(cipherFile);
                    byte[] decryptedBytes = key.unlockAsBytes(readCipherText, createdFingerprints.get(fingerprint1).toCharArray());
                    assertTrue(Arrays.equals(clearbytes, decryptedBytes));
                    System.out.println("LCT test  OK on iteration "+i);
                    i++;
                }
            }
        }catch(Exception e){

            System.out.println("LCT1 "+e.getClass().getName()+"\n "+ e.getMessage());
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement:stackTraceElements){
                System.out.println(stackTraceElement.toString());
            }
        }
    }
}
