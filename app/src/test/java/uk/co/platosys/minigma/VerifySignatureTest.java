package uk.co.platosys.minigma;

import org.junit.Before;
import org.junit.Test;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class VerifySignatureTest {

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
    public void verifySignatureTest(){
        Key key=null;
        Lock lock=null;
        File signatureFile=null;
        LockStore lockStore=null;
        for(Fingerprint fingerprint:createdFingerprints.keySet()){
         try {
            key = new Key(new File(TestValues.keyDirectory, fingerprint.toBase64String()));
            Signature signature = key.sign(TestValues.testText, TestValues.testPassPhrases[0].toCharArray());
            System.out.println(Kidney.toString(signature.getKeyID())+":"+signature.getShortDigest());
            signatureFile = new File(TestValues.signatureDirectory, signature.getShortDigest());
            if (signatureFile.exists()) {
                signatureFile.delete();
            }
            signature.encodeToFile(signatureFile);
            lock = lockStore.getLock(fingerprint);
            //System.out.println(Kidney.toString(lock.getLockID()));
        }catch(Exception e) {
            System.out.println("VST2 "+e.getClass().getName()+"\n "+ e.getMessage());
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement:stackTraceElements){
                System.out.println(stackTraceElement.toString());
            }
        }try{
            Signature rereadSignature = new Signature(signatureFile);
            //System.out.println(Kidney.toString(rereadSignature.getKeyID()));

            assertTrue(lock.verify(TestValues.testText,rereadSignature));
        }catch (Exception e){
            System.out.println("VST3 "+ e.getMessage());
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement:stackTraceElements){
                System.out.println(stackTraceElement.toString());
            }
        }}
    }
    @Test
    public void verifySignatureNotationsTest(){
        Key key=null;
        Lock lock=null;
        File signatureFile=null;
        LockStore lockStore=null;
        try {
            lockStore = new MinigmaLockStore(new File(TestValues.lockDirectory, "lockstore"), false);
        }catch (MinigmaException e){
            Exceptions.dump(e);
        }
        for(Fingerprint fingerprint:createdFingerprints.keySet()){
        try {
            key = new Key(new File(TestValues.keyDirectory,fingerprint.toBase64String()));
            List<Notation> notationList = new ArrayList<>();
            for (int i=0; i<TestValues.testNotationNames.length; i++){
                Notation notation = new Notation(TestValues.testNotationNames[i], TestValues.testNotationValues[i]);
                notationList.add(notation);
            }
            Signature signature = key.sign(TestValues.testText, notationList, TestValues.testPassPhrases[0].toCharArray());
            System.out.println(Kidney.toString(signature.getKeyID())+":"+signature.getShortDigest());
            signatureFile = new File(TestValues.signatureDirectory, signature.getShortDigest());
            if (signatureFile.exists()) {
                signatureFile.delete();
            }
            signature.encodeToFile(signatureFile);
            lock = lockStore.getLock(fingerprint);
            //System.out.println(Kidney.toString(lock.getLockID()));
        }catch(Exception e) {
            Exceptions.dump(e);
        }try{
            Signature rereadSignature = new Signature(signatureFile);
            List<Notation> notations = rereadSignature.getNotations();
            for(Notation notation:notations){
                String notationName = notation.getName();
                String notationValue = notation.getValue();
                System.out.println(notationName + ":"+notationValue);
            }

            assertTrue(lock.verify(TestValues.testText,rereadSignature));
        }catch (Exception e){
           Exceptions.dump(e);
        }
    }}
}
