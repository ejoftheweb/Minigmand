package uk.co.platosys.minigma;
/* (c) copyright 2018, 2019 Platosys
        * MIT Licence
        * Permission is hereby granted, free of charge, to any person obtaining a copy
        * of this software and associated documentation files (the "Software"), to deal
        * in the Software without restriction, including without limitation the rights
        * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        * copies of the Software, and to permit persons to whom the Software is
        * furnished to do so, subject to the following conditions:
        *
        *The above copyright notice and this permission notice shall be included in all
        * copies or substantial portions of the Software.
        *
        * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        * SOFTWARE.*/
import org.spongycastle.openpgp.PGPSignature;

import java.io.InputStream;
import java.text.ParseException;
import java.util.Arrays;

import uk.co.platosys.minigma.exceptions.MinigmaException;

/**A Certificate is a special sort of Signature, where the thing being signed is someone's Lock. If you
 * ltrust the person who signed the Certificate, you can ltrust the Lock it signs. (Important Note:
 * "ltrust" is a shorthand for 'trust that the Lock concerned is theirs': it does not mean that you can trust
 * any of the people involved to buy you a pint. It is just about the binding between
 * the Lock and its owner.)
 * OpenPGP (PGP v4+) supports a number of different types of certification/signature, depending on the value
 * of the signature type octet in a signature. See RFC4880, para 11.
 *
 *  0x00: Binary Document (see Signature) BINARY_DOCUMENT
 *  0x01: Canonical Text Document (see Signature) CANONICAL_TEXT_DOCUMENT
 *  0x02: Standalone Signature (see Signature) STAND_ALONE
 *
 *  --
 * (The following is copied directly from RFC4880 with the addition of the BouncyCastle PGPSignature constant
 * field names)
 *
 *    0x10: Generic certification of a User ID and Public-Key packet. 16
 *        The issuer of this certification does not make any particular
 *        assertion as to how well the certifier has checked that the owner
 *        of the key is in fact the person described by the User ID.
 *        DEFAULT_CERTIFICATION
 *
 *    0x11: Persona certification of a User ID and Public-Key packet. 17
 *        The issuer of this certification has not done any verification of
 *        the claim that the owner of this key is the User ID specified.
 *        NO_CERTIFICATION
 *
 *    0x12: Casual certification of a User ID and Public-Key packet. 18
 *        The issuer of this certification has done some casual
 *        verification of the claim of identity.
 *        CASUAL_CERTIFICATION
 *
 *    0x13: Positive certification of a User ID and Public-Key packet. 19
 *        The issuer of this certification has done substantial
 *        verification of the claim of identity.
 *        POSITIVE_CERTIFICATION
 *
 *        Most OpenPGP implementations make their "key signatures" as 0x10
 *        certifications.  Some implementations can issue 0x11-0x13
 *        certifications, but few differentiate between the types.
 *
 *    0x18: Subkey Binding Signature  24
 *        This signature is a statement by the top-level signing key that
 *        indicates that it owns the subkey.  This signature is calculated
 *        directly on the primary key and subkey, and not on any User ID or
 *        other packets.  A signature that binds a signing subkey MUST have
 *        an Embedded Signature subpacket in this binding signature that
 *        contains a 0x19 signature made by the signing subkey on the
 *        primary key and subkey.
 *        SUBKEY_BINDING
 *
 *    0x19: Primary Key Binding Signature
 *        This signature is a statement by a signing subkey, indicating
 *        that it is owned by the primary key and subkey.  This signature
 *        is calculated the same way as a 0x18 signature: directly on the
 *        primary key and subkey, and not on any User ID or other packets.
 *        PRIMARYKEY_BINDING
 *
 *    0x1F: Signature directly on a key
 *        This signature is calculated directly on a key.  It binds the
 *        information in the Signature subpackets to the key, and is
 *        appropriate to be used for subpackets that provide information
 *        about the key, such as the Revocation Key subpacket.  It is also
 *        appropriate for statements that non-self certifiers want to make
 *        about the key itself, rather than the binding between a key and a
 *        name.
 *        DIRECT_KEY
 *
 *    0x20: Key revocation signature
 *        The signature is calculated directly on the key being revoked.  A
 *        revoked key is not to be used.  Only revocation signatures by the
 *        key being revoked, or by an authorized revocation key, should be
 *        considered valid revocation signatures.
 *        KEY_REVOCATION
 *
 *    0x28: Subkey revocation signature
 *        The signature is calculated directly on the subkey being revoked.
 *        A revoked subkey is not to be used.  Only revocation signatures
 *        by the top-level signature key that is bound to this subkey, or
 *        by an authorized revocation key, should be considered valid
 *        revocation signatures.
 *        SUBKEY_REVOCATION
 *
 *    0x30: Certification revocation signature
 *        This signature revokes an earlier User ID certification signature
 *        (signature class 0x10 through 0x13) or direct-key signature
 *        (0x1F).  It should be issued by the same key that issued the
 *        revoked signature or an authorized revocation key.  The signature
 *        is computed over the same data as the certificate that it
 *        revokes, and should have a later creation date than that
 *        certificate.
 *        CERTIFICATION_REVOCATION
 *
 *    0x40: Timestamp signature.
 *        This signature is only meaningful for the timestamp contained in
 *        it.
 *        TIMESTAMP
 *
 *    0x50: Third-Party Confirmation signature.
 *        This signature is a signature over some other OpenPGP Signature
 *        packet(s).  It is analogous to a notary seal on the signed data.
 *        A third-party signature SHOULD include Signature Target
 *        subpacket(s) to give easy identification.  Note that we really do
 *        mean SHOULD.  There are plausible uses for this (such as a blind
 *        party that only sees the signature, not the key or source
 *        document) that cannot include a target subpacket.
 *        (not supported under BouncyCastle as far as I can see)
 *
 *
 */
public final class Certificate extends BaseSignature {

    public static final int DEFAULT = PGPSignature.DEFAULT_CERTIFICATION;
    public static final int NONE= PGPSignature.NO_CERTIFICATION;
    public static final int CASUAL= PGPSignature.CASUAL_CERTIFICATION;
    public static final int POSITIVE = PGPSignature.POSITIVE_CERTIFICATION;
    public static final int SUBKEY_BINDING=PGPSignature.SUBKEY_BINDING;
    public static final int PRIMARYKEY_BINDING=PGPSignature.PRIMARYKEY_BINDING;
    public static final int KEY_REVOCATION = PGPSignature.KEY_REVOCATION;
    public static final int CERTIFICATION_REVOCATION=PGPSignature.KEY_REVOCATION;
    public static final int SUBKEY_REVOCATION=PGPSignature.SUBKEY_REVOCATION;

    public static int[] CERTIFICATION_TYPES = {
            PGPSignature.DEFAULT_CERTIFICATION,
            PGPSignature.NO_CERTIFICATION,
            PGPSignature.CASUAL_CERTIFICATION,
            PGPSignature.POSITIVE_CERTIFICATION,
            PGPSignature.PRIMARYKEY_BINDING,
            PGPSignature.SUBKEY_BINDING,
            PGPSignature.CERTIFICATION_REVOCATION,
            PGPSignature.KEY_REVOCATION,
            PGPSignature.DIRECT_KEY
    };

    /**
     * Instantiates a Minigma Certificate object from a BouncyCastle PGPSignature object.
     *
     * @param pgpSignature
     * @throws MinigmaException if the PGPSignature isn't a certificate.
     */
    public Certificate(PGPSignature pgpSignature) throws MinigmaException {
        super (pgpSignature);
        if(!(pgpSignature.isCertification())){
            throw new MinigmaException("Signature "+getShortDigest()+" is not a Certificate");
        }
    }
    public Certificate(String string) throws MinigmaException , ParseException {
        super (string);
        if(!(pgpSignature.isCertification())){
            throw new MinigmaException("Signature "+getShortDigest()+" is not a Certificate");
        }
    }
    public Certificate(BigBinary bigBinary) throws MinigmaException {
        super (bigBinary);
        if(!(pgpSignature.isCertification())){
            throw new MinigmaException("Signature "+getShortDigest()+" is not a Certificate");
        }
    }
    public Certificate(InputStream inputStream) throws MinigmaException {
        super (inputStream);
        if(!(pgpSignature.isCertification())){
            throw new MinigmaException("Signature "+getShortDigest()+" is not a Certificate");
        }
    }
    private void init() throws MinigmaException{
        switch (getSignatureType()) {
            case PGPSignature.BINARY_DOCUMENT:
                throw new MinigmaException("Signature "+getShortDigest()+" is not a Certificate");
            case PGPSignature.CANONICAL_TEXT_DOCUMENT:
                throw new MinigmaException("Signature "+getShortDigest()+" is not a Certificate");
            case PGPSignature.STAND_ALONE:
                throw new MinigmaException("Signature "+getShortDigest()+" is not a Certificate");
            case PGPSignature.DEFAULT_CERTIFICATION:
            case PGPSignature.NO_CERTIFICATION:
            case PGPSignature.CASUAL_CERTIFICATION:
            case PGPSignature.POSITIVE_CERTIFICATION:
            case PGPSignature.SUBKEY_BINDING:
            case PGPSignature.PRIMARYKEY_BINDING:
            case PGPSignature.DIRECT_KEY:
            case PGPSignature.KEY_REVOCATION:
            case PGPSignature.SUBKEY_REVOCATION:
            case PGPSignature.CERTIFICATION_REVOCATION:
            case PGPSignature.TIMESTAMP:
            default:
        }
    }
    @Override
    public boolean equals(Object object){
        if (object instanceof Certificate){
            Certificate certificate = (Certificate) object;
            if (Arrays.equals(getBytes(),certificate.getBytes())){
                return true;
            }else{
                /*byte[] certbytes=certificate.getBytes();
                for (int i=0; i<getBytes().length; i++){
                    if (getBytes()[i] !=certbytes[i]){
                        System.out.println("at index"+i+":"+getBytes()[i]+", "+certbytes[i]);
                    }
                }*/
                return false;
            }
        }else{
            System.out.println("Certificate equals: type mismatch");
            return false;
        }
    }
    public int getType() {
        return getSignatureType();
    }
}

