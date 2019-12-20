package passwordmanager;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Password {

  // #######################################################
  // # Static constants. Default values.
  // #######################################################

  // Configuration values
  public static final String KEY_FACTORY_TYPE = "PBKDF2WithHmacSHA512";
  public static final int    ITERATIONS       = 65536;
  public static final int    KEY_SIZE         = 256;
  public static final int    SALT_BYTES       = 32;

  // Exception messages
  public static final String ERROR_BAD_ALGORITHM  = "[Hash error] bad algorithm";
  public static final String ERROR_BAD_SPEC       = "[Hash error] bad key specification";

  // #######################################################
  // # Instance variables
  // #######################################################

  private String password;
  private String salt;

  // #######################################################
  // # Salt utilities
  // #######################################################

  /**
   * @return A random 32-byte (256 bit) salt value as a
   *         Base64-encoded string.
   */
  public static String generateRandomSalt() {
    SecureRandom random = new SecureRandom();
    byte[] saltBytes = new byte[SALT_BYTES];
    random.nextBytes(saltBytes);
    return Base64.getEncoder().encodeToString(saltBytes);
  }

  // #######################################################
  // # Constructors
  // #######################################################

  /**
   * Construct from a passed password and salt (short constructor).
   * The iterations and keySize fields are set to the class's
   * defaults for these values.
   *
   * @param password A plaintext password
   * @param salt     A password salt value (as a string)
   */
  public Password(String password, String salt) {
    this.setPassword(password);
    this.setSalt(salt);
  }

  /**
   * Copy constructor. Construct from an existing
   * PasswordConfig object.
   *
   * @param other Another PasswordConfig object to copy
   */
  public Password(Password other) {
    this.setPassword(other.getPassword());
    this.setSalt(other.getSalt());
  }

  // #######################################################
  // # Getters
  // #######################################################

  /**
   * @return The currently set plaintext password.
   */
  public String getPassword() {
    return this.password;
  }

  /**
   * @return The currently set password salt value.
   */
  public String getSalt() {
    return this.salt;
  }

  // #######################################################
  // # Setters
  // #######################################################

  /**
   * Set the raw (plaintext) password. This method should
   * throw an exception (the type of the exception is up
   * to you) if there is an attempt to set an WEAK password
   *
   * @TODO Implement password strength testing
   *
   * @param password A plaintext password.
   */
  public void setPassword(String password) {
      
      /*(?=.*[a-z]) The string must contain at least 1 lowercase alphabetical character

         *(?=.*[A-Z]) The string must contain at least 1 uppercase
            alphabetical character

         *(?=.*[0-9]) The string must contain at least 1 numeric character

         *(?=.[!@#\$%\^&]) The string must contain at least one special character, but we are escaping reserved RegEx characters to avoid conflict

         *(?=.{8,}) The string must be eight characters or longer*/
        
//        String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\\$%\\^&\\*])(?=.{8,})";
//
//        Pattern pattern = Pattern.compile(regex);
//
//        Matcher matcher = pattern.matcher(password);
//
//        if (!matcher.matches()) {
//            throw new IllegalArgumentException("The Password Does Not Meet The Minimum Requarments");
//        }
        this.password = password;
  }

  /**
   * Set the salt value to be used when hashing the
   * current object's password. This method should
   * throw an exception (the type of the exception is up
   * to you) if there is an attempt to set an WEAK salt
   *
   * @TODO Implement validation
   *    Question 1: Should the salt be of a minimum length
   *    Question 2: What is that minimum length?
   *
   * @param salt A password salt value (as a string)
   */
  public void setSalt(String salt) {
      byte[] saltlength = salt.getBytes();
      if(saltlength.length >= 32){
       this.salt = salt;
      }else{System.out.println("The Salt Must Be Equal Or Greater Than 32 Bytes");}
  }

  // #######################################################
  // # Hashing Utilities
  // #######################################################

  /**
   * Returns a derived key (hash) that has been generated using
   * PBKDF2 (configurable with the KEY_FACTORY_TYPE constant) and
   * SHA512 over {getIterations()} iterations. The resulting hash
   * is returned as a base64-encoded string.
   *
   * @return Hash as a base64-encoded string.
   * @throws PasswordException if the hashing function is not
   *                       correctly configured.
   */
  public String generateHash() {

    try {

      char[] passwordChars     = this.getPassword().toCharArray();
      byte[] saltBytes         = Base64.getDecoder().decode(this.getSalt());

      SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY_TYPE);
      PBEKeySpec       spec    = new PBEKeySpec(passwordChars, saltBytes, ITERATIONS, KEY_SIZE);
      SecretKey        key     = factory.generateSecret(spec);
                                                    // needs an array of bytes must use key.getEncoded()
      return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    catch(NoSuchAlgorithmException e) {
      throw new PasswordException(ERROR_BAD_ALGORITHM);
    }
    catch(InvalidKeySpecException e) {
      throw new PasswordException(ERROR_BAD_SPEC);
    }
  }

  /**
   * Returns true if the passed hash is equal to the result
   * of hashing the current password data (i.e. like calling
   * this.generateHash() and comparing its result to the
   * passed hash)
   *
   * @param hash The pre-computed hash to compare.
   *
   * @return true if the passed and computed hashes match
   * @throws PasswordException if the hashing function is not
   *                       correctly configured.
   */
  public boolean matchesHash(String hash) {
    return this.generateHash().equals(hash);
  }

}
