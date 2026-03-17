/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

import java.security.MessageDigest;

// decrypt
class SecureUDPproxy {
    private static final String SEED_GCM = "0123456789abcdef";
    private static final String SEED_CHACHA = "0123456789abcdefghijklmnopqrstuv";
    public static long numberOFiterations = 48;

    private static final int IV_SIZE_GCM = 12; // 16 ctr 12 for gcm
    private static final int IV_SIZE_CHACHA = 12;

    // private static final int
    private static byte[] PRFKeyGen() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        // byte[] keyBytes = SEED_CUSTOM.getBytes();
        SecretKey key = generateKey("AES");

        long counter;
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext;
        byte[] firstHalf;
        byte[] secondHalf;
        byte[] hashfirstHalf;
        byte[] hashsecondHalf;
        byte[] result = new byte[16];

        for (counter = 0; counter < numberOFiterations; counter++) {
            ciphertext = cipher.doFinal(key.getEncoded());
            int mid = ciphertext.length / 2;

            // copyOfRange(array, start, end) -> end is exclusive
            firstHalf = Arrays.copyOfRange(ciphertext, 0, mid);
            secondHalf = Arrays.copyOfRange(ciphertext, mid, ciphertext.length);
            hashfirstHalf = digest.digest(firstHalf);
            hashsecondHalf = digest.digest(secondHalf);
            result = xorArrays(hashfirstHalf, hashsecondHalf);

            key = new SecretKeySpec(result, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

        }
        return result;

    }

    private static SecretKey generateKey(String encryptionType) throws Exception {
        if (!((encryptionType.equals("AES")) || (encryptionType.equals("CHACHA"))
                || (encryptionType.equals("CUSTOM")))) {
            throw new IllegalArgumentException("encryption type not allowed");
        }
        byte[] keyBytes = null;
        if (encryptionType.equals("AES")) {
            keyBytes = SEED_GCM.getBytes(); // 128-bit key

        }
        if (encryptionType.equals("CHACHA")) {
            keyBytes = SEED_CHACHA.getBytes(); // 256-bit key
            encryptionType = "ChaCha20";
        }

        return new SecretKeySpec(keyBytes, encryptionType);
    }

    public static byte[] xorArrays(byte[] a, byte[] b) {
        // Both arrays must be the same length for a standard XOR
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static byte[] extendKey(byte[] key, int length, long nonce) {
        byte[] extended = new byte[length];

        // convert nonce to bytes
        ByteBuffer nonceBuffer = ByteBuffer.allocate(8);
        nonceBuffer.putLong(nonce);
        byte[] nonceBytes = nonceBuffer.array();

        for (int i = 0; i < length; i++) {
            // mix key byte + nonce byte (cycling through nonce too)
            extended[i] = (byte) (key[i % key.length] ^ nonceBytes[i % nonceBytes.length]);
        }
        return extended;
    }

    public static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream("config.properties");
        if (args.length != 1) {
            System.out.print("specify algorithm");
            System.exit(-1);
        }
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        String Algorithm = args[0].trim();
        if (!(Algorithm.equals("AES") || Algorithm.equals("CHACHA") || (Algorithm.equals("CUSTOM")))) {
            System.out.println("wrong encryption method inserted");
        }
        SecretKey key = null;
        byte[] key_custom = null;
        if ((Algorithm.equals("AES") || Algorithm.equals("CHACHA"))) {
            key = generateKey(Algorithm); // AES ou CHACHA
        }
        if (Algorithm.equals("CUSTOM")) {
            key_custom = PRFKeyGen();
        }

        Properties properties = new Properties();
        properties.load(inputStream);
        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        System.out.println("remote" + remote);
        System.out.println("destinations:" + destinations);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s))
                .collect(Collectors.toSet());

        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024 + 64];
        System.out.println("i work");
        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket); // if remote is unicast
            System.out.println("aqui1");
            System.out.print(".");
            DatagramPacket packet = new DatagramPacket(buffer, inPacket.getLength());
            ByteBuffer bb = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
            System.out.println("aqui2");
            byte[] decryptedData = null;

            if (Algorithm.equals("AES")) {

                byte[] iv = new byte[IV_SIZE_GCM];
                bb.get(iv);
                byte[] ciphertext = new byte[bb.remaining()];
                bb.get(ciphertext);
                try {
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    GCMParameterSpec spec = new GCMParameterSpec(128, iv); // --------> mode with
                    cipher.init(Cipher.DECRYPT_MODE, key, spec);
                    decryptedData = cipher.doFinal(ciphertext);

                } catch (Exception e) {
                    System.err.println("Decryption failed for block ");
                }
            }
            if (Algorithm.equals("CHACHA")) {
                byte[] iv = new byte[IV_SIZE_CHACHA];
                bb.get(iv);
                byte[] ciphertext = new byte[bb.remaining()];
                bb.get(ciphertext);
                try {
                    Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                    IvParameterSpec spec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, key, spec);
                    decryptedData = cipher.doFinal(ciphertext);
                } catch (Exception e) {
                    System.err.println("Decryption failed for block ");
                }

            }
            if (Algorithm.equals("CUSTOM")) {
                long nonce = bb.getLong(); // read prepended nonce
                byte[] ciphertext = new byte[bb.remaining()];
                bb.get(ciphertext);
                try {
                    byte[] extendedKey = extendKey(key_custom, ciphertext.length, nonce);
                    decryptedData = xorArrays(ciphertext, extendedKey);
                } catch (Exception e) {
                    System.err.println("Decryption failed for block ");
                }
            }
            if (decryptedData != null) {

                for (SocketAddress outSocketAddress : outSocketAddressSet) {
                    outSocket.send(new DatagramPacket(decryptedData, decryptedData.length, outSocketAddress));

                }
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
