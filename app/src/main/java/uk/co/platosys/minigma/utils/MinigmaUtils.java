package uk.co.platosys.minigma.utils;

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

//import android.util.Base64;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;


import java.util.Date;



import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.openpgp.PGPCompressedDataGenerator;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPLiteralDataGenerator;
import org.spongycastle.util.Strings;
import org.spongycastle.util.encoders.UrlBase64;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.bc.BcPGPObjectFactory;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;

import uk.co.platosys.minigma.Minigma;


/**A general utility class to encode/decode bytes to Base64.
 *
 * This class has been refactored to use the BouncyCastle Base64 encoders, removing the dependency on
 * either the java or Android ones.
 *
 * Note that by default, the encode/decode methods use standard Base64 encoding using Table 1 of RFC 4648.
 * This includes characters that are unsafe to use in URLs and some filenames. If you want to use Table 2, urlsafe,
 * use the methods that take a urlsafe boolean argument.  This behaviour may change in later releases,
 * to defend against which it probably makes sense always to specify whether to use urlsafe encoding or not.
 *
 */


public class MinigmaUtils {

    static PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(Minigma.COMPRESS_ALGORITHM);
    static PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();


    /** turns a byte array into a Base-64 encoded string using standard (Table 1 of RFC 4648) encoding **/
    public static String encode(byte[] bytes){
        return Base64.toBase64String(bytes);
    }
    /** turns a byte array into a Base-64 encoded string; if urlsafe is true, uses Table 2 of RFC 4648,
     * otherwise it uses Table 1.  **/
    public static String encode(byte[] bytes, boolean urlsafe){
        if (urlsafe) {
            return Strings.fromByteArray(UrlBase64.encode(bytes));
        }else{
            return encode(bytes);
        }
    }
    /**treats a long as a byte array of size 8 and encodes it as a url/filename safe Base-64 string*/
    public static String encode (long hash){
        byte bytes[] = new byte[8];
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        byteBuffer.putLong(hash);
        return encode(bytes, true);
    }
    /** turns a base-64 encoded string into a byte array */
    public static byte[] decode(String string){
        return Base64.decode(string);
    }
    /** turns a URL-safe base-64 encoded string into a byte array */
    public static byte[] decode(String string, boolean urlsafe){
        if(urlsafe){
            return UrlBase64.decode(string);
        }else return decode(string);
    }
    /**converts an ordinary String  into an array of bytes**/
    public static byte[] toByteArray(String string){
        return string.getBytes(Charset.forName("UTF-8"));
    }
    /**converts an array of bytes into a String*/
    public static String fromByteArray(byte[] asBytes){
        return new String(asBytes, Charset.forName("UTF-8"));
    }
    /**compresses a byte array of clear data
     * @param clearData a byte-array of clear, uncompressed data
     * @return a byte-array of clear, compressed data
     * */
    public static byte[] compress(byte[] clearData){
        printBytes(clearData);
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            OutputStream compressedOut = compressor.open(byteOut);
            OutputStream  literalOut = literalDataGenerator.open(compressedOut,
                    PGPLiteralData.BINARY,
                    "compressed",
                    clearData.length,
                    new Date());

            literalOut.write(clearData);
            literalOut.close();
            compressor.close();

            byte[] bytesOut = byteOut.toByteArray();
            printBytes(bytesOut);
            return bytesOut;
        }catch (IOException e){
            return null;
        }

    }
    public static void printBytes (byte[] bytes){
        /*for (byte byt:bytes){
            System.out.print(byt);
        }
        System.out.print("\n");*/
    }

    /** Takes a byteArray of cyphertext and encodes it to an AsciiArmored file
     * @param file
     * @param cyphertext
     */
    public static void encodeToArmoredFile(File file, byte[] cyphertext) throws IOException{
        MinigmaOutputStream armoredOutputStream = new MinigmaOutputStream(new FileOutputStream(file));

        armoredOutputStream.write(cyphertext);
        armoredOutputStream.flush();
        armoredOutputStream.close();

    }
    public static void writeToBinaryFile(File file, byte[] data) throws IOException{
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(data);
        fileOutputStream.flush();
        fileOutputStream.close();
    }
    public static byte[] readFromArmoredFile(File armoredFile) throws IOException{
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(new FileInputStream(armoredFile));

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int read;
        byte[] data = new byte[1024];
        while ((read = armoredInputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, read);
        }

        buffer.flush();
        return  buffer.toByteArray();

    }
    public static byte[] readFromBinaryFile(File file) throws IOException{
        return readStream(new FileInputStream(file));
    }

    /**
     * Reads an inputStream into a byte array. This method has no checks on stream length
     * so needs to be used carefully - if the stream is indeterminate, an OutOfMemory exception will
     * eventually crash everything.
     * @param inputStream
     * @return
     * @throws IOException
     */
    public static byte[] readStream(InputStream inputStream) throws IOException{
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int read;
        byte[] data = new byte[1024];
        while ((read = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, read);
        }
        buffer.flush();
        return  buffer.toByteArray();
    }

}