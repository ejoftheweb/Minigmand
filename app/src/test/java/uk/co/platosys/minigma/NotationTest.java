package uk.co.platosys.minigma;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class NotationTest {
    Key key;
    Signature signature;
    List<Notation> notations;
    char[][]passphrases;
    @Before
    public void setup() {
        try {
            for (char[] passphrase:passphrases) {
                notations = new ArrayList<>();
                for (int i = 0; i < TestValues.testNotationNames.length; i++) {
                    notations.add(new Notation(TestValues.testNotationNames[i], TestValues.testNotationValues[i]));
                }
               // key = new Key(new File(TestValues.keyDirectory, TestValues.testUsernames[0]));
                //signature = key.sign(TestValues.testText, notations, passphrase);
            }
        } catch (Exception x) {

        }
    }
    @Test
    public void testNotations(){

    }

}
