package uk.co.platosys.minigma;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import uk.co.platosys.minigma.exceptions.Exceptions;

public class NotationTest {
    Key key;
    Signature signature;
    List<Notation> notations;
    char[][]passphrases;


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
    public void testNotations(){

    }

}
