package uk.co.platosys.minigma;
/* (c) copyright 2018 Platosys
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

import org.spongycastle.openpgp.PGPPublicKey;

import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.utils.Base64;

import java.nio.*;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * Fingerprint is an object wrapper to a byte array used to identify
 * keys and locks.
 * An OpenPGP fingerprint is a 160-bit/20-byte number used to confirm keys and locks.
 */
public class Fingerprint {
    private byte[] fingerprintbytes;
    public Fingerprint(byte[] fingerprint){
        this.fingerprintbytes=fingerprint;
    }

    /**Compares this Fingerprint with another and returns true if and only if they match.
     *
     * @param object
     * @return
     */
    @Override
    public boolean equals(Object object){
        try {
            Fingerprint fingerprint = (Fingerprint) object;
            return Arrays.equals(fingerprintbytes, fingerprint.getFingerprintbytes());
        }catch(ClassCastException ccx){
            return false;
        }
    }
    /**Returns this Fingerprint as a Base64 encoded String**/
    @Override
    public String toString(){
        try {
            return Base64.encode(fingerprintbytes, true);
        }catch(Exception x){}
        return null;
    }
    /**Returns this Fingerprint as a byte array.
     *
     * @return
     */
    public byte[] getFingerprintbytes() {
        return fingerprintbytes;
    }

    /**
     * The OpenPGP long keyID is the 8 low-order bytes of  the fingerprint.
     * Generally, we prefer to use the 20-byte fingerprint rather than the
     * 8-byte keyID as an identifier, as the collision risk is thus vanishingly
     * small, but the underlying BouncyCastle implementation uses the shorter keyID as
     * do quite a few public keyservers.  Since a fingerprint is 20 bytes / 160 bits,
     * this method returns the lowest 8 bytes/64 bits as a Java long primitive.
     * @return
     */
    public long getKeyID(){
        try{
            byte[] loworderbytes = new byte[8];
            for (int i=0; i<8; i++){
                loworderbytes[i]=fingerprintbytes[i+12];
            }
            return (ByteBuffer.wrap(loworderbytes)).getLong();
        }catch (Exception x){
            Exceptions.dump(x);
            return 0;
        }
    }
    /**Returns a list of words representing this Fingerprint.
     * Human-mediated comparison of fingerprints is an important part of maintaining the security of
     * a distributed crypto-system based on Web-of-Trust.  It is much less error-prone for most people
     * to compare natural language words than streams of numbers.
     * This returns a list of English words as long as the fingerprint (currently 20 bytes).
     * They are selected from the PGP word list.
     *
     * @return
     */
    public  List<String> getFingerprint() {
        ArrayList<String> arrayList= new ArrayList<>();
        boolean even = true;
        for (byte sbyte:fingerprintbytes){
            int fbyte=sbyte;
            if(fbyte<0){fbyte=fbyte+256;}
            //System.out.println(fbyte+" "+String.format("%x", fbyte));
            if (even) {
                //System.out.println(EVEN_BIOMES[fbyte]);
                arrayList.add(EVEN_BIOMES[fbyte]);
                even=false;
            }else{
                //System.out.println(ODD_BIOMES[fbyte]);

                arrayList.add(ODD_BIOMES[fbyte]);
                even=true;
            }
        }

        return arrayList;
    }

    /**
     * Returns length words vaguely identifying the PGPPublicKey  in question, enough for testing but not for proving
     * @param length
     * @return
     */
    public static String getTestFingerprint(PGPPublicKey pgpPublicKey, int length){
        try {
            Fingerprint fingerprint = new Fingerprint(pgpPublicKey.getFingerprint());
            List<String> fp = fingerprint.getFingerprint();
            StringBuffer buffer=new StringBuffer();// = new String[length];
            Iterator<String> fpit = fp.iterator();
            int i=0;
            while (fpit.hasNext() && i<length){
                buffer.append(fpit.next());
                buffer.append(" ");
                i++;
            }
            return buffer.toString();
        } catch (Exception x){
            Exceptions.dump("FP-GTF", x);
            return null;
        }
    }

    public static final  String [] EVEN_BIOMES =new String[] {
            "aardvark", "absurd", "accrue", "acme", "adrift",
            "adult", "afflict", "ahead", "aimless", "Algol",
            "allow", "alone", "ammo", "ancient", "apple",
            "artist", "assume", "Athens", "atlas", "Aztec",
            "baboon", "backfield", "backward", "banjo", "beaming",
            "bedlamp", "beehive", "beeswax", "befriend", "Belfast",
            "berserk", "billiard", "bison", "blackjack", "blockade",
            "blowtorch", "bluebird", "bombast", "bookshelf", "brackish",
            "breadline", "breakup", "brickyard", "briefcase", "Burbank",
            "button", "buzzard", "cement", "chairlift", "chatter",
            "checkup", "chisel", "choking", "chopper", "Christmas",
            "clamshell", "classic", "classroom", "cleanup", "clockwork",
            "cobra", "commence", "concert", "cowbell", "crackdown",
            "cranky", "crowfoot", "crucial", "crumpled", "crusade",
            "cubic", "dashboard", "deadbolt", "deckhand", "dogsled",
            "dragnet", "drainage", "dreadful", "drifter", "dropper",
            "drumbeat", "drunken", "Dupont", "dwelling", "eating",
            "edict", "egghead", "eightball", "endorse", "endow",
            "enlist", "erase", "escape", "exceed", "eyeglass",
            "eyetooth", "facial", "fallout", "flagpole", "flatfoot",
            "flytrap", "fracture", "framework", "freedom", "frighten",
            "gazelle", "Geiger", "glitter", "glucose", "goggles",
            "goldfish", "gremlin", "guidance", "hamlet", "highchair",
            "hockey", "indoors", "indulge", "inverse", "involve",
            "island", "jawbone", "keyboard", "kickoff", "kiwi",
            "klaxon", "locale", "lockup", "merit", "minnow",
            "miser", "Mohawk", "mural", "music", "necklace",
            "Neptune", "newborn", "nightbird", "Oakland", "obtuse",
            "offload", "optic", "orca", "payday", "peachy",
            "pheasant", "physique", "playhouse", "Pluto", "preclude",
            "prefer", "preshrunk", "printer", "prowler", "pupil",
            "puppy", "python", "quadrant", "quiver", "quota",
            "ragtime", "ratchet", "rebirth", "reform", "regain",
            "reindeer", "rematch", "repay", "retouch", "revenge",
            "reward", "rhythm", "ribcage", "ringbolt", "robust",
            "rocker", "ruffled", "sailboat", "sawdust", "scallion",
            "scenic", "scorecard", "Scotland", "seabird", "select",
            "sentence", "shadow", "shamrock", "showgirl", "skullcap",
            "skydive", "slingshot", "slowdown", "snapline", "snapshot",
            "snowcap", "snowslide", "solo", "southward", "soybean",
            "spaniel", "spearhead", "spellbind", "spheroid", "spigot",
            "spindle", "spyglass", "stagehand", "stagnate", "stairway",
            "standard", "stapler", "steamship", "sterling", "stockman",
            "stopwatch", "stormy", "sugar", "surmount", "suspense",
            "sweatband", "swelter", "tactics", "talon", "tapeworm",
            "tempest", "tiger", "tissue", "tonic", "topmost",
            "tracker", "transit", "trauma", "treadmill", "Trojan",
            "trouble", "tumor", "tunnel", "tycoon", "uncut",
            "unearth", "unwind", "uproot", "upset", "upshot",
            "vapor", "village", "virus", "Vulcan", "waffle",
            "wallet", "watchword", "wayside", "willow", "woodlark",
            "Zulu"};
    public static final String[] ODD_BIOMES= new String[] {
            "adroitness","adviser", "aftermath","aggregate","alkali",
            "almighty","amulet","amusement","antenna","accident",
            "Apollo","armistice", "article","asteroid","Atlantic",
            "atmosphere","autopsy","babylon","backwater","barbecue",
            "belowground","bifocals","bodyguard","bookseller","borderline",
            "bottomless","Bradbury","bravado","Brazilian","breakaway",
            "Burlington","businessman","butterfat","Camelot","candidate",
            "cannonball","capricorn","caravan","caretaker","celebrate",
            "cellulose","certify","chambermaid","Cherokee","Chicago",
            "clergyman","coherence","combustion","commando","company",
            "component","concurrent","confidence","conformist","congregate",
            "consensus","consulting","corporate","corrosion","councilman",
            "crossover","crucifix","cumbersome","customer","Dakota",
            "decadence","December","decimal","designing","detector",
            "detergent","determine","dicator","dinosaur","direction",
            "disable","disbelief","disruptive","distortion","document",
            "embezzle","enchanting","enrolment","enterprise","equation",
            "equipment","escapade","Eskimo","everyday","examine",
            "existence","exodus","fascinate","filament","finicky",
            "forever","fortitude","frequency","gadetry","Galveston",
            "getaway","glossary","gossamer","graduate","gravity",
            "guitarist","hamburger","Hamilton","handiwork","hazardous",
            "headwaters","hemisphere","hesitate","hideaway","holiness",
            "hurricane","hydraulic","impartial","impetus","inception",
            "indigo","inertia","infancy","inferno","informant",
            "insincere","insurgent","integrate","intention","inventive",
            "Istanbul","Jamaica","Jupiter","leprosy","letterhead",
            "liberty","maritime","matchmaker","maverick","Medusa",
            "megaton","microscope","microwave","midsummer","millionaire",
            "miracle","misnomer","molasses","molecule","Montana",
            "monument","mosquito","narrative","nebula","newsletter",
            "Norwegian","October","Ohio","onlooker","opulent",
            "Orlando","outfielder","Pacific","pandemic","Pandora",
            "paperweight","paragon","paragraph","paramount","passenger",
            "pedigree","pegasus","penetrate","perceptive","performance",
            "pharmacy","phonetic","photograph","pioneer","pocketful",
            "politeness","positive","potato","processor","provincial",
            "proximate","puberty","publiser","pyramid","quantity",
            "racketeer","rebellion","recipe","recover","repellent",
            "replica","reproduce","resistor","responsive","retraction",
            "retrieval","retrospect","revenue","revival","revolver",
            "sandalwood","sardonic","Saturday","savagery","scavenger",
            "sensation","sociable","souvenir","specialist","speculate",
            "stethoscope","stupendous","supportive","surrender","suspicious",
            "sympathy","tambourine","telephone","therapist","tobacco",
            "tolerance","tomorrow","torpedo","tradition","travesty",
            "trombonist","truncated","typewriter","ultimate","undaunted",
            "underfoot","unicorn","unify","universe","unravel",
            "upcoming","vacancy","vagabond","vertigo","Virginia",
            "visitor","vocalist","voyager","warranty","Waterloo",
            "whimsical","Wichita","Wilmington","Wyoming","yesteryear",
            "Yucatan"};



}

