/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

class SecureStreamServer {
	public static long numberOFiterations = 48;

	// encrypt
	private static SecretKey generateKey(String encryptionType) throws Exception {
		if (!((encryptionType.equals("AES")) || (encryptionType.equals("CHACHA"))
				|| (encryptionType.equals("CUSTOM")))) {
			throw new IllegalArgumentException("encryption type not allowed");
		}
		byte[] keyBytes = null;
		if (encryptionType.equals("AES")) {
			keyBytes = "0123456789abcdef".getBytes(); // 128-bit key

		}
		if (encryptionType.equals("CHACHA")) {
			keyBytes = "0123456789abcdefghijklmnopqrstuv".getBytes(); // 128-bit key
		}

		return new SecretKeySpec(keyBytes, encryptionType);
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

	public static byte[] xorArrays(byte[] a, byte[] b) {
		// Both arrays must be the same length for a standard XOR
		byte[] result = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			result[i] = (byte) (a[i] ^ b[i]);
		}
		return result;
	}

	private static final int IV_SIZE_CHACHA = 12;
	private static final int IV_SIZE = 12; // 12 for gcm 16 for ctr

	static public void main(String[] args) throws Exception {
		if (args.length != 4) {
			System.out.println("Erro, usar: mySend <movie> <ip-multicast-address> <port> <encryption>");
			System.out.println("        or: mySend <movie> <ip-unicast-address> <port> <encryption>");
			System.exit(-1);
		}
		String Algorithm = args[3].trim();

		int size;
		int csize = 0;
		int count = 0;
		long time;
		byte[] key_custom = null;
		SecretKey key = null;
		if (((Algorithm.equals("AES")) || (Algorithm.equals("CHACHA")))) {
			key = generateKey(Algorithm);

		}
		if (Algorithm.equals("CUSTOM")) {
			key_custom = PRFKeyGen();

		}

		DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
		byte[] buff = new byte[4096];

		DatagramSocket s = new DatagramSocket();

		InetSocketAddress addr = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
		long t0 = System.nanoTime(); // Ref. time
		long q0 = 0;

		// Movies are encoded in .dat files, where each
		// frame is encoded in a real-time sequence of MP4 frames
		// Somewhat an FFMPEG4 playing scheme .. Dont worry

		// Each frame has:
		// Short size || Long Timestamp || byte[] EncodedMP4Frame
		// You can read (frame by frame to transmit ...
		// But you must folow the "real-time" encoding conditions

		// OK let's do it !
		SecureRandom random = new SecureRandom();

		while (g.available() > 0) {

			size = g.readUnsignedShort(); // size of the frame
			csize = csize + size;
			time = g.readLong(); // timestamp of the frame
			if (count == 0)
				q0 = time; // ref. time in the stream
			DatagramPacket pencrypt = null;
			if (Algorithm.equals("AES")) {
				byte[] iv = new byte[IV_SIZE];
				random.nextBytes(iv);
				GCMParameterSpec spec = new GCMParameterSpec(128, iv);
				byte[] buffer = new byte[size];
				g.readFully(buffer, 0, size);
				Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
				cipher.init(Cipher.ENCRYPT_MODE, key, spec);
				byte[] ciphertext = cipher.doFinal(buffer, 0, size);

				// DatagramPacket pencrypt = new DatagramPacket(ciphertext, ciphertext.length,
				// addr);
				byte[] ivAndCipher = new byte[IV_SIZE + ciphertext.length];
				System.arraycopy(iv, 0, ivAndCipher, 0, IV_SIZE);
				System.arraycopy(ciphertext, 0, ivAndCipher, IV_SIZE, ciphertext.length);
				pencrypt = new DatagramPacket(ivAndCipher, ivAndCipher.length, addr);
			}
			if (Algorithm.equals("CHACHA")) {
				byte[] iv = new byte[IV_SIZE_CHACHA];
				random.nextBytes(iv);
				IvParameterSpec spec = new IvParameterSpec(iv);
				byte[] buffer = new byte[size];
				g.readFully(buffer, 0, size);
				Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
				cipher.init(Cipher.ENCRYPT_MODE, key, spec);
				byte[] ciphertext = cipher.doFinal(buffer, 0, size);

				// DatagramPacket pencrypt = new DatagramPacket(ciphertext, ciphertext.length,
				// addr);
				byte[] ivAndCipher = new byte[IV_SIZE_CHACHA + ciphertext.length];
				System.arraycopy(iv, 0, ivAndCipher, 0, IV_SIZE_CHACHA);
				System.arraycopy(ciphertext, 0, ivAndCipher, IV_SIZE_CHACHA, ciphertext.length);
				pencrypt = new DatagramPacket(ivAndCipher, ivAndCipher.length, addr);
			}
			if (Algorithm.equals("CUSTOM")) {
				byte[] buffer = new byte[size];
				g.readFully(buffer, 0, size);

				byte[] extendedKey = extendKey(key_custom, buffer.length, count); // count increments per frame
				byte[] ciphertext = xorArrays(extendedKey, buffer);
				// prepend nonce to packet so proxy can decrypt
				ByteBuffer out = ByteBuffer.allocate(8 + ciphertext.length);
				out.putLong(count);
				out.put(ciphertext);
				pencrypt = new DatagramPacket(out.array(), out.array().length, addr);

			}
			// byte[] iv = new byte[IV_SIZE];
			// random.nextBytes(iv);
			// GCMParameterSpec spec = new GCMParameterSpec(128, iv);
			// byte[] buffer = new byte[size];
			// g.readFully(buffer, 0, size);
			// Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			// cipher.init(Cipher.ENCRYPT_MODE, key, spec);
			// byte[] ciphertext = cipher.doFinal(buffer, 0, size);

			// // DatagramPacket pencrypt = new DatagramPacket(ciphertext,
			// ciphertext.length,
			// // addr);
			// byte[] ivAndCipher = new byte[IV_SIZE + ciphertext.length];
			// System.arraycopy(iv, 0, ivAndCipher, 0, IV_SIZE);
			// System.arraycopy(ciphertext, 0, ivAndCipher, IV_SIZE, ciphertext.length);
			// DatagramPacket pencrypt = new DatagramPacket(ivAndCipher, ivAndCipher.length,
			// addr);

			count += 1;
			// g.readFully(buff, 0, size);
			// p.setData(buff, 0, size);
			// p.setSocketAddress(addr);

			long t = System.nanoTime(); // what time is it?

			// Decision about the right time to transmit
			Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

			// send datagram (udp packet) w/ payload frame)
			// Frames sent in clear (no encryption)

			s.send(pencrypt);

			// Just for awareness ... (debug)

			System.out.print(":");
		}

		long tend = System.nanoTime(); // "The end" time
		System.out.println();
		System.out.println("DONE! all frames sent: " + count);

		long duration = (tend - t0) / 1000000000;
		System.out.println("Movie duration " + duration + " s");
		System.out.println("Throughput " + count / duration + " fps");
		System.out.println("Throughput " + (8 * (csize) / duration) / 1000 + " Kbps");

	}
}
