import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

public class BeastAttack {

    public static void main(String[] args) throws Exception {

        byte[] ciphertext = new byte[1024]; // will be plenty big enough
        // default prefix
        byte[] prefix = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        // first get the initial IV and record the time
        int length = callEncrypt(null, 0, ciphertext);
        byte[] iv = Arrays.copyOfRange(ciphertext, 0, 8);
        Instant now = Instant.now();


        for (int y = 7; y >= 0; y--) {

            for (int x = 0; x < 7; x++) {
                prefix[x] = prefix[x + 1];
            }

            // predict latest IV and encrypt with y byte prefix
            // this will return cipher text from E(<0,0,0,0,0,0,0,(m1^iv8)>)

            length = predictAndEncrypt(now, iv, prefix, y, ciphertext);
            byte[] lastiv = Arrays.copyOfRange(ciphertext, 0, 8);

            // this is the cipher block we need to find later
            byte[] cblock = Arrays.copyOfRange(ciphertext, 8, 16);

            // print cblock which is what we're looking for
            printBlock(cblock);

            byte[] fblock = new byte[8];

            for (int i = y; i < 7; i++) {
                prefix[i] = (byte) (prefix[i] ^ lastiv[i]);
            }

            // now encrypt all prefixes whilst varying byte 8
            for (int x = 0; x < 256; x++) {

                // change the last byte of the prefix
                prefix[7] = (byte) x;

                // predict latest IV and encrypt with 8 byte prefix
                // this will return cipher text from E(<0,0,0,0,0,0,0,x>)
                length = predictAndEncrypt(now, iv, prefix, 8, ciphertext);

                // this is the cipher block we need to compare with cblock
                fblock = Arrays.copyOfRange(ciphertext, 8, 16);

                if (compareBlocks(fblock, cblock)) {
                    printBlock(fblock);
                    // fblock and cblock are the same so
                    // E(<0,0,0,0,0,0,0,(m1^iv8)>) == E(<0,0,0,0,0,0,0,x>)
                    // (m1^iv8) == x
                    // m1 == (x^iv8)
                    System.out.println("Found");
                    System.out.println(String.format("%02x ", x));

                    prefix[7] = (byte) (x ^ lastiv[7]);
                    System.out.println(prefix[7]);

                    for (int i = y; i < 7; i++) {
                        prefix[i] = (byte) (prefix[i] ^ lastiv[i]);
                    }

                    break;
                }

                System.out.print(".");
            }
        }

        printBlock(prefix);
        for (int x = 0; x < 8; x++) {
            System.out.print((char) (byte) prefix[x]);
        }
    }


    static int predictAndEncrypt(Instant then, byte[] iv, byte[] prefix, int len, byte[] ciphertext) throws IOException {
        byte[] piv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] aiv = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        Instant now;
        long milliseconds;
        int length = 0;

        // keep trying until the predicted IV is returned
        while (!compareBlocks(aiv, piv)) {
            now = Instant.now();
            milliseconds = Duration.between(then, now).toMillis();

            // add some function of the number of milliseconds passed since getting the initial iv
            piv = longToBytes(bytesToLong(iv) + (milliseconds * 5 + 50));

            // call encrypt with the predicted IV
            length = callEncrypt(xorBlocks(prefix, piv), len, ciphertext);

            // get returned IV
            aiv = Arrays.copyOfRange(ciphertext, 0, 8);

            //System.out.println("Trying IV");
            //printBlock(piv);
            //System.out.println("Received IV");
            //printBlock(aiv);
            //System.out.println("");
        }

        return length;
    }


    // a helper method to call the external programme "encrypt" in the current directory
    // the parameters are the plaintext, length of plaintext, and ciphertext; returns length of ciphertext
    static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        Process process;

        // run the external process (don't bother to catch exceptions)
        if (prefix != null) {
            // turn prefix byte array into hex string
            byte[] p = Arrays.copyOfRange(prefix, 0, prefix_len);
            String PString = adapter.marshal(p);
            process = Runtime.getRuntime().exec("./encrypt " + PString);
        } else {
            process = Runtime.getRuntime().exec("./encrypt");
        }

        // process the resulting hex string
        String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
        byte[] c = adapter.unmarshal(CString);
        System.arraycopy(c, 0, ciphertext, 0, c.length);
        return (c.length);
    }


    public static void printBlock(byte[] block) {
        for (int x = 0; x < block.length; x++) {
            // print each byte of the block
            System.out.print(String.format("%02x", block[x]));
        }

        System.out.println("");
    }

    public static boolean compareBlocks(byte[] block1, byte[] block2) {
        for (int i = 0; i < block1.length; i++) {
            if (block1[i] != block2[i]) {
                return false;
            }
        }
        return true;
    }

    public static byte[] xorBlocks(byte[] block1, byte[] block2) {
        byte[] newBlock = new byte[block1.length];
        for (int x = 0; x < block1.length; x++) {
            // xor each pair of bytes
            newBlock[x] = (byte) (block1[x] ^ block2[x]);
        }
        return newBlock;
    }

    static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    static long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();
        return buffer.getLong();
    }

}

// Task 1
// The IV varies with time.


