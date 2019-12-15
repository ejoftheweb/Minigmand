package uk.co.platosys.minigma;

import org.spongycastle.openpgp.PGPSignature;

/**
 * Class containing relevant constants
 */
public class Constants {

    public static int[] SIGNATURE_TYPES = {
            PGPSignature.BINARY_DOCUMENT,
            PGPSignature.CANONICAL_TEXT_DOCUMENT,
            PGPSignature.STAND_ALONE,
            PGPSignature.TIMESTAMP
    };
}
