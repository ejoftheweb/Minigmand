package uk.co.platosys.minigma.utils;

import uk.co.platosys.minigma.exceptions.MinigmaException;

public class Base64 {
    public final static char[] TABLE2 = {
      'A','B','C','D','E','F','G','H','I','J','K','L','M',
      'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
      'a','b','c','d','e','f','g','h','i','j','k','l','m',
      'n','o','p','q','r','s','t','u','v','w','x','y','z',
       '0','1','2','3','4','5','6','7','8','9','-','_','='
    };
    public final static char[] TABLE1 = {
            'A','B','C','D','E','F','G','H','I','J','K','L','M',
            'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m',
            'n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9','+','/','='
    };

    public static String encode (byte[] bytes, boolean urlsafe) throws MinigmaException {
        if (bytes.length > Integer.MAX_VALUE) {throw new MinigmaException("Base64: trying to convert too big an array");}
        char[] table;
        if(urlsafe){table=TABLE2;}else{table=TABLE1;}
        int len=0;
        int pad = bytes.length%3;
        switch (pad){
            case 0:
                len=(bytes.length/3);
                break;
            case 1:
                len=((bytes.length-1)/3);
                break;
            case 2:
                len=((bytes.length-2)/3);
                break;
        }
        for (int i=0; i<len; i++){
            StringBuffer buffer = new StringBuffer();
            buffer.append(Integer.toBinaryString(bytes[(3*i)]));

        }
    return null;
    }
}
