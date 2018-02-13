/*
 *
    * (c) copyright 2018 Platosys
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
         * SOFTWARE.
 */

package uk.co.platosys.minigma.utils;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
/**
 *
 * @author edward
 */
public class FileTools {
    /**
     * Recursively deletes files and directories and their contents (equivalent to rm -r )
     * (assumes no permission issues, doesn't trap them yet);
     */
    public static void delete(File file){
        if(!file.isDirectory()){
            file.delete();
        }else{
            File[] files = file.listFiles();
            for (int i=0; i<files.length; i++){
                delete(files[i]);
            }
            file.delete();
        }
    }
    /**this removes spaces and any funny characters from the supplied string, but keeps dots.
     *
     * handy to process strings to make them more useful as cross-platform filenames
     *
     * @param string
     * @return
     */
    public static String removeFunnyCharacters(String string){
        StringBuffer buffer = new StringBuffer();
        char dot = '.';
        for (int i=0; i<string.length(); i++){
            char x = string.charAt(i);
            if (Character.isLetterOrDigit(x)){
                buffer.append(x);
            }
            if (x==dot){buffer.append(x);}
        }
        return new String(buffer);
    }
    /**
     * simple file copy utility
     * @param fromFile
     * @param toFile
     * @throws IOException
     */
    public static void copy(File fromFile, File toFile)
            throws IOException {


        if (!fromFile.exists())
            throw new IOException("FileCopy: " + "no such source file: "
                    + fromFile.getAbsolutePath());
        if (!fromFile.isFile())
            throw new IOException("FileCopy: " + "can't copy directory: "
                    + fromFile.getAbsolutePath());
        if (!fromFile.canRead())
            throw new IOException("FileCopy: " + "source file is unreadable: "
                    + fromFile.getAbsolutePath());

        if (toFile.isDirectory())
            toFile = new File(toFile, fromFile.getName());

        if (toFile.exists()) {
            if (!toFile.canWrite())
                throw new IOException("FileCopy: "
                        + "destination file is unwriteable: " + toFile.getAbsolutePath());
            System.out.print("Overwrite existing file " + toFile.getName()
                    + "? (Y/N): ");
            System.out.flush();
            BufferedReader in = new BufferedReader(new InputStreamReader(
                    System.in));
            String response = in.readLine();
            if (!response.equals("Y") && !response.equals("y"))
                throw new IOException("FileCopy: "
                        + "existing file was not overwritten.");
        } else {
            String parent = toFile.getParent();
            if (parent == null)
                parent = System.getProperty("user.dir");
            File dir = new File(parent);
            if (!dir.exists())
                throw new IOException("FileCopy: "
                        + "destination directory doesn't exist: " + parent);
            if (dir.isFile())
                throw new IOException("FileCopy: "
                        + "destination is not a directory: " + parent);
            if (!dir.canWrite())
                throw new IOException("FileCopy: "
                        + "destination directory is unwriteable: " + parent);
        }

        FileInputStream from = null;
        FileOutputStream to = null;
        try {
            from = new FileInputStream(fromFile);
            to = new FileOutputStream(toFile);
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = from.read(buffer)) != -1)
                to.write(buffer, 0, bytesRead); // write
        } finally {
            if (from != null)
                try {
                    from.close();
                } catch (IOException e) {

                }
            if (to != null)
                try {
                    to.close();
                } catch (IOException e) {

                }
        }
    }
}

