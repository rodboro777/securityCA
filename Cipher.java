package passwordmanager;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class Cipher {

  // #######################################################
  // # Static constants. Default values.
  // #######################################################

  // Configuration values
  public static final String CIPHER_TYPE     = "AES/CBC/PKCS5Padding";
  public static final String KEY_SPEC_TYPE   = "AES";
  public static final int    BITS_PER_BYTE   = 8;
  public static final int    KEY_BITS_SMALL  = 128;
  public static final int    KEY_BITS_MEDIUM = 192;
  public static final int    KEY_BITS_LARGE  = 256;


  // Exception messages
  public static final String PREPEND_ENCRYPT = "[ENCRYPT]";
  public static final String PREPEND_DECRYPT = "[DECRYPT]";
  public static final String BAD_KEY_SIZE    = "A 128, 192, or 256-byte key is required (encoded as Base64)";

  // #######################################################
  // # Encryption utility
  // #######################################################

  /**
   * Returns true if the passed byte array is of size 128,
   * 192, or 256 bits -- the only acceptable key sizes for
   * AES.
   */
  public static boolean isValidKeySize(byte[] key) {

    // Convert byte count to bit count
    int keyLengthBits = key.length * BITS_PER_BYTE;

    // Ensure bit count is valid for an AES key
    return keyLengthBits == KEY_BITS_SMALL
        || keyLengthBits == KEY_BITS_MEDIUM
        || keyLengthBits == KEY_BITS_LARGE;
  }

  /**
   * Given a string of plaintext, and a 128, 192, or 256-bit
   * key (encoded as base-64) encrypts the string using
   * AES256-CBC (configurable in CIPHER_TYPE const).
   *
   * Note the returned string bundles the initialization
   * vector and ciphertext, separated by a | character.
   *
   * @param plaintext The plaintext string to encrypt
   * @param base64Key The key to use for encryption, 128, 192, or 256
   *                  bytes as a base64-encoded string
   * @return          Encrypted ciphertext as a base64-encoded string
   *                  the initialization vector and ciphertext are
   *                  both included, separated by a | character
   */
  public static String encryptString(String plaintext, String base64Key) {

    // Decode the base64-encoded key into bytes
    byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);

    // Check the key is a usable length
    if (!Cipher.isValidKeySize(decodedKeyBytes)) {
      throw new CipherException(BAD_KEY_SIZE);
    }

    try {

      // Create a native key specification object.
      SecretKey secret = new SecretKeySpec(decodedKeyBytes, KEY_SPEC_TYPE);

      // Initialize the cipher algorithm
      javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_TYPE);
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret);

      // Get the block initialization vector
      byte[] ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

      // Encrypt the plaintext
      byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

      // Base64-encode the initialization vector and ciphertext bytes
      return Base64.getEncoder().encodeToString(ivBytes)
          + "|"
          + Base64.getEncoder().encodeToString(ciphertext);
    }
    catch (NoSuchAlgorithmException |NoSuchPaddingException |InvalidKeyException |IllegalBlockSizeException |BadPaddingException |InvalidParameterSpecException e) {
      throw new CipherException(PREPEND_ENCRYPT + e.getMessage());
    }
  }

  // #######################################################
  // # Decryption utility
  // #######################################################

  /**
   * Given a string of ciphertext created with the encryptString
   * method, and a 128, 192, or 256-bit key (encoded as base-64),
   * decrypts the string using AES256-CBC (configurable in
   * CIPHER_TYPE const).
   *
   * @param ciphertext The ciphertext string to decrypt, inclusive
   *                   of initialization vector (format: iv|ciphertext).
   * @param base64Key  The key to use for encryption, 128, 192, or 256
   *    *              bytes as a base64-encoded string
   * @return           Decrypted Plaintext string
   */
  public static String decryptString(String ciphertext, String base64Key) {

    // Decode the base64-encoded key into bytes
    byte[] decodedKeyBytes = Base64.getDecoder().decode(base64Key);

    // Check the key is a usable length
    if (!Cipher.isValidKeySize(decodedKeyBytes)) {
      throw new CipherException(BAD_KEY_SIZE);
    }

    try {

      // Decode Base64 string into IV and ciphertext bytes
      String[] cipherTextParts = ciphertext.split("\\|");
      byte[]   ivBytes         = Base64.getDecoder().decode(cipherTextParts[0]);
      byte[]   ciphertextBytes = Base64.getDecoder().decode(cipherTextParts[1]);

      // Create a native key specification object
      SecretKey secret = new SecretKeySpec(decodedKeyBytes, KEY_SPEC_TYPE);

      // Initialize the cipher algorithm
      javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(CIPHER_TYPE);
      cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

      // Decode and return the plaintext
      String plaintext = new String(cipher.doFinal(ciphertextBytes));
      return plaintext;
    }
    catch (NoSuchAlgorithmException |NoSuchPaddingException |InvalidKeyException |IllegalBlockSizeException |BadPaddingException |InvalidAlgorithmParameterException e) {
      throw new CipherException(PREPEND_DECRYPT + e.getMessage());
    }
  }

}
