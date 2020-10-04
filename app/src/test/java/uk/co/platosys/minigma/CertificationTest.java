package uk.co.platosys.minigma;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.junit.Test;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.Assert.assertTrue;

public class CertificationTest {
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
    public void selfCertificationTest(){
        System.out.println("Running Single Certification Test");
        boolean masterselfsigned=false;
        boolean encryptselfsigned=false;
        boolean signselfsigned=false;
        for (String fingerprint:fingerprints.keySet()){
        try {
            Lock lock = lockstore.getLock(new Fingerprint(fingerprint));
            Iterator<PGPPublicKeyRing> publicKeyRingIterator = lock.getPGPPublicKeyRingIterator();
            while(publicKeyRingIterator.hasNext()){
                PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingIterator.next();
                Iterator<PGPPublicKey> publicKeyIterator = pgpPublicKeyRing.getPublicKeys();
                while (publicKeyIterator.hasNext()){
                    PGPPublicKey pgpPublicKey = publicKeyIterator.next();
                    String sfprint = Fingerprint.getTestFingerprint(pgpPublicKey, 2);
                    if (pgpPublicKey.isMasterKey()){
                        Iterator iterator = pgpPublicKey.getSignatures();
                        while (iterator.hasNext()){
                            PGPSignature pgpSignature = (PGPSignature) iterator.next();
                            if (pgpSignature.getKeyID()==lock.getLockID()){
                                masterselfsigned=true;
                            }
                        }
                    }else if (pgpPublicKey.isEncryptionKey()){
                        Iterator iterator = pgpPublicKey.getSignatures();
                        while (iterator.hasNext()){
                            PGPSignature pgpSignature = (PGPSignature) iterator.next();
                            if (pgpSignature.getKeyID()==lock.getLockID()){
                                encryptselfsigned=true;
                            }
                        }
                    }else{
                        Iterator iterator = pgpPublicKey.getSignatures();
                        while (iterator.hasNext()){
                            PGPSignature pgpSignature = (PGPSignature) iterator.next();
                            if (pgpSignature.getKeyID()==lock.getLockID()){
                                signselfsigned=true;
                            }
                        }
                    }
                }
                //System.out.println("keycount: "+keycount);
                //ringcount++;
            }
            assertTrue(masterselfsigned&&encryptselfsigned&&signselfsigned);
        }catch (Exception x){
            Exceptions.dump("SCT", x);
        }
    }}
    @After
    @Test
    public void multipleCertificationTest(){
        //1.For each testuser 0-9
            // Get a lock and certify it by testusers 0-9.
            // Save it to the lockstore.
        ////
        //2. For each testuser 0-9
        //     Retrieve the lock and get its certifications;
        //      for each certification:
        //         verify the certificate signature
        //      //
             //
        System.out.println("Running Certification Test");
        try {
            System.out.println("Running Certification Test (CT1)");

            Map<String, Certificate> certificatesMap = new HashMap<>();
            for (String fingerprint:fingerprints.keySet()){
                Lock lock =lockstore.getLock(new Fingerprint(fingerprint));
                for (String signername: fingerprints.keySet()){
                    Key key = new Key(new File(TestValues.keyDirectory, signername),lockstore);
                    char[] passphrase = fingerprints.get(signername).toCharArray();
                    Iterator<PGPPublicKeyRing> publicKeyRingIterator = lock.getPGPPublicKeyRingIterator();
                    int ringcount=0;
                    while(publicKeyRingIterator.hasNext()){
                        PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingIterator.next();
                        Iterator<PGPPublicKey> publicKeyIterator = pgpPublicKeyRing.getPublicKeys();
                        //int keycount=0;
                        while (publicKeyIterator.hasNext()){
                            //each basic lock has 3 keys, master, encryption, signing.

                            PGPPublicKey pgpPublicKey = publicKeyIterator.next();
                            Certificate certificate = lock.certify(pgpPublicKey.getKeyID(), key, passphrase,lockstore,Certificate.DEFAULT);
                            certificatesMap.put(certificate.getShortDigest(), certificate);
                           // keycount++;
                        }
                        //System.out.println("keycount: "+keycount);
                        //ringcount++;
                    }
                    //System.out.println("ringcount: "+ringcount);
                }
            }

            System.out.println("Running Certification Test CT2");
            for (String username:fingerprints.keySet()){
                Lock lock = lockstore.getLock(new Fingerprint(username));
                System.out.println("CT2 testing certificates for "+username+"'s lock, id:"+Kidney.toString(lock.getLockID()));
                List<Certificate> certificates = lock.getCertificates();
                System.out.println("CT2 lock "+Kidney.toString(lock.getLockID())+" has "+certificates.size()+" certificates");
                for(Certificate certificate:certificates){
                    System.out.println("\tCT2 attached certificate"+certificate.getShortDigest()+" was signed by "+lockstore.getUserID(certificate.getKeyID()));
                    try {
                        if(certificatesMap.containsKey(certificate.getShortDigest())) {
                            Certificate certificate1 = certificatesMap.get(certificate.getShortDigest());
                            System.out.println("\t CT2 certificate in collection "+certificate1.getShortDigest()+" was signed by "+lockstore.getUserID(certificate1.getKeyID()));
                            assertTrue(certificate.equals(certificate1));
                        }else{
                            System.out.println("\tCT2 certificate "+certificate.getShortDigest()+" not found in collection");
                        }
                    }catch(NullPointerException npe){
                        Exceptions.dump(npe);
                    }


                }

            }
        }catch(Exception x){
            Exceptions.dump(x);
        }
    }
    @Test
    public void certificateRevocationTest(){
        System.out.println("Running Certificate Revocation Test");
        try {
            LockStore lockstore = new MinigmaLockStore(TestValues.lockFile, false);
            for(String username: fingerprints.keySet()) {
                Lock lock = lockstore.getLock(new Fingerprint(username));
                Fingerprint fingerprint = lock.getFingerprint();
                Key key = new Key(new File(TestValues.keyDirectory, username), lockstore);

                lock.revokeLock(fingerprint, key, TestValues.testPassPhrases[0].toCharArray());
                List<Certificate> certificatesList = lock.getCertificates();
                for (Certificate certificate : certificatesList) {
                    if (certificate.getType() == PGPSignature.KEY_REVOCATION) {
                        System.out.println("Certificate is Revoked");
                    }

                }
            }
        }catch(Exception e){
            Exceptions.dump(e);
        }

    }
}
