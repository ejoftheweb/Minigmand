package uk.co.platosys.minigma.exceptions;
/**Exception thrown when invalid/badly-formed XML is produced by the XMLUtils class*/
public class InvalidXMLException extends Exception {

        public InvalidXMLException (String msg){
            super(msg);

        }
        public InvalidXMLException (String msg, Throwable cause){
            super(msg, cause);

        }

}
