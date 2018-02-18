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
     * You can specify alternative wordlists supported by Effwords. At the moment, Effwords only
     * supports the three EFF lists.
     *
     *
     *
     */
    private  File wordListFile;
    private List<String> wordList;
    public  static int WORDLIST_SIZE=1297;
    public static final String WORDSEPARATOR = " ";
    public static final char WORDSEPARATOR_CHAR=' ';
    public static int LONGWORDLIST=Effwords.EFF_LONGLIST;
    public static int SHORTWORDLIST=Effwords.EFF_SHORTLIST;
    public static int ALTWORDLIST=Effwords.EFF_DEFAULTLIST;

    public static char[] getPassPhrase(int words) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuffer buffer= new StringBuffer();
        for (int i = 0; i < words; i++) {
            try {
                int word = secureRandom.nextInt(WORDLIST_SIZE);
                if (i > 0) {
                    buffer.append(WORDSEPARATOR);
                }
                buffer.append(Effwords.getWord(Effwords.EFF_LONGLIST,word));
            }catch (Exception x) {
                Exceptions.dump(x);
            }
        }
        return buffer.toString().toCharArray();
    }
    public static char[] getPassPhrase(int wordList, int words) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuffer buffer= new StringBuffer();
        for (int i = 0; i < words; i++) {
            try {
                int word = secureRandom.nextInt(WORDLIST_SIZE);
                if (i > 0) {
                    buffer.append(WORDSEPARATOR);
                }
                buffer.append(Effwords.getWord(wordList,word));
            }catch (Exception x) {
                Exceptions.dump(x);
            }
        }
        return buffer.toString().toCharArray();
    }
    //this method really belongs in minigmand.passphraser, it will get there eventually.
    public  List<String> toWordList(char[] passphrase) {
        ArrayList<String> words = new ArrayList<>();
        StringBuffer stringBuffer = new StringBuffer();
        for (char ch : passphrase) {
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

