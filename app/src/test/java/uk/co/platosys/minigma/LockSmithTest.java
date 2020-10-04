package uk.co.platosys.minigma;

import org.junit.BeforeClass;
import org.junit.Test;
import uk.co.platosys.minigma.exceptions.DuplicateNameException;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.FileTools;
import static org.junit.Assert.*;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class LockSmithTest {
    File testRoot = new File("/home/edward/platosys/test/minigma");
    File keyDirectory = new File(testRoot,"keys");
    File lockDirectory = new File(testRoot, "lockstore");
   String[] testPassPhrases=TestValues.testPassPhrases;//"ABCDEFG", "BCDEFGH", "CDEFGHI", "DEFGHIJ", "EFGHIJK", "FGHIJKL", "GHIJKLM", "HIJKLMN", "IJKLMNO", "JKLMNOP"};
    String testText = "Phlebas the Phoenician, a fortnight dead, " +
            "forgot the cry of gulls and the deep sea swell";
    File cipherDirectory=new File (testRoot, "ciphertext");
    File clearDirectory=new File (testRoot, "cleartext");
    LockStore lockStore;
    Map<String,String> fingerprints = new HashMap<>();
    @Test
    public void createMultipleLockSetTest(){
        System.out.println("Running LockSmithTest: CreateMultipleLockset Test (CMLT)");
        testRoot.mkdirs();
        keyDirectory.mkdirs();
        lockDirectory.mkdirs();
        boolean duplicateName=false;
         File lockFile = new File(lockDirectory, "lockstore");

        try {
           lockStore = new MinigmaLockStore(lockFile, true);
           for (int i=0; i<testPassPhrases.length; i++) {
               //File keyFile = new File(keyDirectory, FileTools.removeFunnyCharacters(testUsernames[i]));
               try {
                   long startTime=System.currentTimeMillis();
                   Lock lock = LockSmith.createLockset(keyDirectory, lockStore,  testPassPhrases[i].toCharArray(), Algorithms.RSA);
                   fingerprints.put(lock.getFingerprint().toBase64String(), testPassPhrases[i]);
                   long endTime=System.currentTimeMillis();
                   long takenTime=endTime-startTime;

               }catch(DuplicateNameException dnx){
                   System.out.println(dnx.getMessage());
               }
           }
        }catch(Exception e){
            System.out.println(e.getMessage());
            System.out.println(e.getCause().getMessage());

        }

        assertTrue(lockFile.exists());
        for (String fp:fingerprints.keySet()){
           File keyfile = new File(keyDirectory, fp);
           assertTrue(keyfile.exists());
           try{
               Key key = new Key(keyfile);
               Lock lock = lockStore.getLock(new Fingerprint(fp));
               String ciphertext = lock.lockAsString(testText);
               String clearText = key.unlock(ciphertext, fingerprints.get(fp).toCharArray());
               assertTrue(clearText.equals(testText));


           }catch (MinigmaException mx){
               System.out.println (mx.getMessage());
           }
        }

    }

}
