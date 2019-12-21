
package uk.co.platosys.minigma;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.*;
import org.spongycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.spongycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.spongycastle.openpgp.operator.PGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import uk.co.platosys.minigma.Key;
import uk.co.platosys.minigma.Lock;
import uk.co.platosys.minigma.Minigma;
import uk.co.platosys.minigma.exceptions.BadPassphraseException;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.MinigmaOtherException;
import uk.co.platosys.minigma.utils.Kidney;
import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 * Class containing static methods to do signing and verifying.
 *
 * @author edward
 */
public class SignatureEngine {
    private static String TAG ="SignatureEngine";



    protected static Signature sign(String string, Key key, char [] passphrase) throws BadPassphraseException, MinigmaOtherException{
        byte[] bytes = MinigmaUtils.toByteArray(string);
        return sign(bytes, key, passphrase);
    }
    protected static Signature sign(String string, Key key, List<Notation> notations,  char [] passphrase) throws BadPassphraseException, MinigmaOtherException{
        byte[] bytes = MinigmaUtils.toByteArray(string);
        return sign(bytes, key, notations, passphrase);
    }
    protected  static Signature sign(BigBinary bigBinary, Key key, List<Notation> notations, char[] passphrase) throws  BadPassphraseException, MinigmaOtherException{
        return (sign (bigBinary.toByteArray(), key, notations, passphrase));
    }
    protected static Signature sign(BigBinary bigBinary, Key key, char[] passphrase) throws BadPassphraseException, MinigmaOtherException{
        return sign(bigBinary.toByteArray(), key, passphrase);
    }
    protected static Signature sign(byte [] bytes, Key key, char[] passphrase) throws BadPassphraseException, MinigmaOtherException {

        PGPPrivateKey privateKey= null;
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        }catch(Exception x) {
        }try {
            PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);

            privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);
        }catch (PGPException pgpx) {
            throw new BadPassphraseException("bad passphrase", pgpx);
        }try{
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
            PGPSignature pgpSignature = signatureGenerator.generate();
            pgpSignature.update(bytes, 0, 0);
            return new Signature(pgpSignature );

        }catch(Exception e){
            throw new MinigmaOtherException("error making signature", e);
        }
    }
    protected static Signature sign(byte [] bytes, Key key, List<Notation> notations, char[] passphrase) throws  BadPassphraseException, MinigmaOtherException{
        PGPPrivateKey privateKey= null;
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        }catch(Exception x) {
        }try {
            PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);

            privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);
        }catch (PGPException pgpx) {
            throw new BadPassphraseException("bad passphrase", pgpx);
        }try{
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
            PGPSignatureSubpacketGenerator pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            for (Notation notation:notations){
                pgpSignatureSubpacketGenerator.setNotationData(notation.isCritical(), notation.isHumanReadable(), notation.getName(), notation.getValue());
            }
            PGPSignatureSubpacketVector pgpSignatureSubpacketVector = pgpSignatureSubpacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(pgpSignatureSubpacketVector);
            PGPSignature pgpSignature = signatureGenerator.generate();
            pgpSignature.update(bytes, 0, 0);
            return new Signature(pgpSignature );

        }catch(Exception e){
            throw new MinigmaOtherException("error making signature", e);
        }
    }

    protected static List<List<Fingerprint>> verify(String string, Signature signature, Lock lock){
        return verify(MinigmaUtils.toByteArray(string), signature, lock);
    }
    static List <List<Fingerprint>> verify (BigBinary bigBinary, Signature signature, Lock lock){
        return verify(bigBinary.toByteArray(), signature, lock);
    }

    /**
     * Returns a List containing two Lists of Fingerprints. The first list contains the Fingerprints of
     * all the Locks whose signature verifies, the second those of all those who either haven't signed the
     * signature or whose signature didn't verify.
     * @param bytes
     * @param signature
     * @param lock
     * @return
     */
    static List <List<Fingerprint>> verify(byte [] bytes, Signature signature, Lock lock){
        List<Fingerprint> signors = new ArrayList<Fingerprint>();
        List<Fingerprint> nonsignors=new ArrayList<Fingerprint>();
        List<List<Fingerprint>> results = new ArrayList<List<Fingerprint>>();
        results.add(signors);
        results.add(nonsignors);
        try{
            KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
            byte [] sigVal = signature.getBytes();
            //Log.d(TAG,"sigVal  = "+Kidney.toString(sigVal));
            ByteArrayInputStream bis = new ByteArrayInputStream(sigVal);
            InputStream in = PGPUtil.getDecoderStream(bis);
            PGPObjectFactory    pgpFactory = new PGPObjectFactory(in, calculator );
            PGPSignatureList    signatureList = null;
            Object    o = pgpFactory.nextObject();
            if (o instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData)o;
                pgpFactory = new PGPObjectFactory(compressedData.getDataStream(), calculator);
                signatureList = (PGPSignatureList)pgpFactory.nextObject();
            }else{
                signatureList = (PGPSignatureList)o;
            }

            for(int i=0; i<signatureList.size(); i++){
                PGPSignature pgpSignature = signatureList.get(i);
                long  keyID = pgpSignature.getKeyID();
                PGPPublicKey publicKey = lock.getPublicKey(keyID);
                PGPContentVerifierBuilderProvider pgpContentVerifierBuilder = new JcaPGPContentVerifierBuilderProvider();//.get(keyAlgorithm, Minigma.HASH_ALGORITHM);
                pgpSignature.init(pgpContentVerifierBuilder, publicKey);
                pgpSignature.update(bytes, 0,0);
                if(pgpSignature.verify()){
                    signors.add(new Fingerprint(publicKey.getFingerprint()));
                }else{
                    nonsignors.add(new Fingerprint(publicKey.getFingerprint()));
                }
            }
        }catch(Exception x){
            Exceptions.dump(x);
        }
        return results;
    }

    /**
     * Returns a BouncyCastle PGPSignature object although it probably ought to be a Certificate?
     * @param key
     * @param passphrase
     * @param keyToBeSigned
     * @param certificationLevel
     * @return
     */
    public static Certificate getKeyCertification(Key key, char[] passphrase, PGPPublicKey keyToBeSigned, int certificationLevel){

        try{
            if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null){
                Security.addProvider(new BouncyCastleProvider());
            }
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
            subPacketGenerator.setRevocable(true,true);
            subPacketGenerator.setSignatureCreationTime(true, new Date());
            PGPSignatureSubpacketVector packetVector = subPacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(packetVector);
            JcePBESecretKeyDecryptorBuilder keyDecryptorBuilder = new JcePBESecretKeyDecryptorBuilder();
            keyDecryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            signatureGenerator.init(certificationLevel, key.getSigningKey().extractPrivateKey(keyDecryptorBuilder.build(passphrase)));
            PGPSignature signature = signatureGenerator.generateCertification(keyToBeSigned);
            return new Certificate(signature);
        }catch(Exception x){
            Exceptions.dump(x);
            return null;
        }
    }

    static Certificate getKeyRevocation(Key key, char [] passphrase, PGPPublicKey keyToBeRevoked){

        try{
            if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null){
                Security.addProvider(new BouncyCastleProvider());
            }
            PGPSecretKey secretKey = key.getSigningKey();
            PBESecretKeyDecryptor keyDecryptor =  new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);
            PGPPrivateKey privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);

            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.DIRECT_KEY,privateKey);
            PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
            subPacketGenerator.setRevocable(true,true);
            subPacketGenerator.setSignatureCreationTime(true, new Date());
            PGPSignatureSubpacketVector packetVector = subPacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(packetVector);
            PGPSignature signature = signatureGenerator.generateCertification(keyToBeRevoked);
            return new Certificate(signature);
        }catch(Exception x){
            Exceptions.dump(x);
            return null;
        }
    }
}