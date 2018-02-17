package uk.co.platosys.minigma;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import uk.co.platosys.effwords.Effwords;
import uk.co.platosys.minigma.exceptions.Exceptions;

public class PassPhraser {
    /**
     *  in the Minigma library, a Key is unlocked with a Passphrase, which is a char array.
     *
     * Passphraser generates random-word passphrases. There is some evidence that random-word
     * passphrases are easier to remember for a similar level of entropy than random-character ones,
     * even though the resulting passphrase is much longer.
     *
     *  Random passphrases are known to be more secure than human-generated ones.     *
     *
     *  Passphraser generates random-word passphrases from the EFF alternative short-list which is 6^4 words
     *  long.
     *
     *
     *
     */
    private  File wordListFile;
    private List<String> wordList;
    public  static int WORDLIST_SIZE=1297;
    public static final String WORDSEPARATOR = " ";
    public static final char WORDSEPARATOR_CHAR=' ';


    public static char[] getPassPhrase(int words) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuffer buffer= new StringBuffer();
        for (int i = 0; i < words; i++) {
            try {
                int word = secureRandom.nextInt(WORDLIST_SIZE);
                if (i > 0) {
                    buffer.append(WORDSEPARATOR);
                }
                buffer.append(Effwords.getWord(Effwords.EFF_DEFAULTLIST,word));
            }catch (Exception x) {
                Exceptions.dump(x);
            }
        }
        return buffer.toString().toCharArray();
    }
    //Returns a String array from a char[].
    public static List<String> toWordList(char[] passphrase) {
        ArrayList<String> words = new ArrayList<>();
        StringBuffer stringBuffer = null;
        for (char ch : passphrase) {
            stringBuffer = new StringBuffer();
            if (ch != WORDSEPARATOR_CHAR) {
                stringBuffer.append(ch);
            } else {
                String word = stringBuffer.toString();
                words.add(word);
                stringBuffer = new StringBuffer();
            }
        }
        if (stringBuffer != null) {
            words.add(stringBuffer.toString());
        }
        return words;
    }

}

