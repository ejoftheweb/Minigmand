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
     *  Random passphrases are known to be more secure than human-generated ones which are
     *
     *
     *  Passphraser generates passphrases from the EFF alternative short-list which is 6^4 words
     *  long.
     *
     *
     *
     */
    private  File wordListFile;
    private List<String> wordList;
    public  static int WORDLIST_SIZE=1297;
    public static final String WORDSEPARATOR = " ";

    public PassPhraser(){

    }
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


}

