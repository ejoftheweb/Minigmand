package uk.co.platosys.minigma;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class PassPhraserTest {
    @Before
    public void setup(){
        System.out.println("Starting Passphraser test");
    }
    @Test
    public void getPassPhraseTest(){
        PassPhraser passPhraser = new PassPhraser();

        System.out.println(passPhraser.getPassPhrase(6));
    }
    @After
    public void finish(){
        System.out.println("Passphraser test finished");
    }
}
