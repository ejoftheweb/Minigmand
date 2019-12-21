package uk.co.platosys.minigma;

import org.junit.Before;
import org.junit.Test;

import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.File;
import java.util.Iterator;
import java.util.List;

import static junit.framework.Assert.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class LockStoreTest {

    File testRoot = new File("/home/edward/platosys/test/minigma");
    File keyDirectory = new File(testRoot,"keys");
    File lockStoreDirectory = new File(testRoot, "lockstore");
    File lockFile = new File("/home/edward/keys/pubring", "ejofat");

    LockStore lockStore = null;
    Lock lock;
    String userID;
    List<String> userIDS;
    @Before
    public void setup() {
        try {
            lockStore = new MinigmaLockStore(lockStoreDirectory, true);
           // System.out.println("Loaded lockstore with "+lockStore.getCount()+" locks");
            lock = new Lock(lockFile);
            userID = lock.getUserID();
            System.out.println(userID);
            userIDS = lock.getUserIDs();
            for(String usid: userIDS){
                System.out.println(usid);
            }
        }catch(Exception x){
            Exceptions.dump(x);
        }
    }
    @Test
    public void loadLockStore(){
        try {
             if (lockStore.addLock(lock)){
                assertTrue(lockStore.contains(userID));
            }else {
                 assertFalse(lockStore.contains(userID));
             }



        }catch(Exception mex){
            Exceptions.dump(mex);

        }

    }

    @Test
    public void testGetLock() {
        try {
            Lock testLock = lockStore.getLock(userID);
            assertTrue(testLock.getLockID() == lock.getLockID());
            List<String> fingerprint = lock.getFingerprint().getFingerprint();
            List<String> nf = testLock.getFingerprint().getFingerprint();
            for (int i = 0; i < fingerprint.size(); i++) {
                System.out.println(fingerprint.get(i)+":"+nf.get(i));
                assertTrue(fingerprint.get(i) == nf.get(i));
            }
        } catch (Exception x) {

        }
    }
}
