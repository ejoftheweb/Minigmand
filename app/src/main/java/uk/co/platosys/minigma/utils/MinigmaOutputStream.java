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
package uk.co.platosys.minigma.utils;

import org.spongycastle.bcpg.ArmoredOutputStream;
import uk.co.platosys.minigma.Minigma;

import java.io.OutputStream;

/**MinigmaOutputStream is a PGP ArmoredOutputStream in which the headers identify Minigma
 * as the user agent
 *
 */
public class MinigmaOutputStream extends ArmoredOutputStream {
    public MinigmaOutputStream (OutputStream outputStream){
        super(outputStream);
        setHeader("Library:", Minigma.LIBRARY_NAME);
        setHeader(ArmoredOutputStream.VERSION_HDR, Minigma.VERSION);
        setHeader("Comment:", "Java/Android OpenPGP API built on a Bouncy Castle");
    }


    /*
    public MinigmaOutputStream (OutputSteam outputStream, Lock lock){
       //data written to this stream will be encrypted with the accompanying Lock.
    }
    public MinigmaOutputSteam (OutputStream outputStream, Lock lock, Key key. char[] passphrase){
    }
     *
     */
    /*
    The functionality of this class, and the corresponding but not-yet-existent MinigmaInputStream will be
         extended to allow for signed and/or encrypted indeterminate streams, for use in an application such as
          secure distributed videoconferencing */
}

