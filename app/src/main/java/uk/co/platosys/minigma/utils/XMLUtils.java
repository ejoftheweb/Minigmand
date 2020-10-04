package uk.co.platosys.minigma.utils;

import org.jdom2.Document;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.XMLOutputter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import uk.co.platosys.minigma.Key;
import uk.co.platosys.minigma.Lock;
import uk.co.platosys.minigma.exceptions.BadPassphraseException;
import uk.co.platosys.minigma.exceptions.InvalidXMLException;

/**
 *  Static methods to handle org.jdom2.Documents
 */
public class XMLUtils {
    public static Document decode(String encoded) throws InvalidXMLException {

        SAXBuilder saxBuilder = new SAXBuilder();
        try{
            return saxBuilder.build(new ByteArrayInputStream(MinigmaUtils.decode(encoded)));
        }catch(Exception x){
            throw new InvalidXMLException("invalid xml", x);
        }

    }
    public static String encode(Document document) throws IOException {
        XMLOutputter xmlOutputter = new XMLOutputter();
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            xmlOutputter.output(document, byteArrayOutputStream);
            return MinigmaUtils.encode(byteArrayOutputStream.toByteArray(),true);
        }catch(IOException iox){
            throw iox;
        }catch(Exception x){

        }
        return null;
    }
    public static Document decrypt(String encrypted, Key key, char[] passphrase) throws InvalidXMLException, BadPassphraseException {
        //TODO
        return null;

    }
    public static String encrypt(Document document, Lock lock){
        //TODO
        return null;
    }

}
