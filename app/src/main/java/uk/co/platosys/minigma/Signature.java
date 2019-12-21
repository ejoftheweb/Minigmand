package uk.co.platosys.minigma;

import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureList;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.MinigmaUtils;

import java.io.*;
import java.text.ParseException;

/**
 * The Signature object  wraps a BouncyCastle PGPSignature object.
 * It can be instantiated from a String, an InputStream or a File.
 * It is often just a list of size 1, containing a single signature.
 *
 *
 *
 */

public  final class Signature extends BaseSignature {

    private long keyID;

    protected Signature (PGPSignature pgpSignature){
        super(pgpSignature);
    }
    public Signature (String string) throws ParseException {
        super(string);
    }
    public Signature (InputStream inputStream, String shortDigest){
        super(inputStream);

    }
    public Signature (File file) throws Exception {
        this( new FileInputStream(file), file.getName());
    }


}

