/*
 * Name: Yahya Angawi
 * Student ID: D00233709
 ** 
 */
package passwordmanager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;


public class Manager {
    
    private static int id;
    private String title, website, password;
    private static LocalDateTime lastUpdated;
    private static final byte[] key = "PASSWORD - STRING".getBytes();
    private static final String transformation = "AES";

    public Manager(String title, String website, String password) {
        this.title = title;
        this.setWebsite(website);
        this.setPassword(password);
        this.lastUpdated = LocalDateTime.now();
        id++;
    }

    public Manager(String website, String password) {
        this.setWebsite(website);
        this.setPassword(password);
        this.lastUpdated = LocalDateTime.now();
        id++;
    }

    public int getId() {
        return id;
    }

    public static void setId(int id) {
        Manager.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getWebsite() {
        return website;
    }
    // Validated as a URL (required input)
    public void setWebsite(String website) {
        
        String regex = "^(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";

        Pattern pattern = Pattern.compile(regex);

        Matcher matcher = pattern.matcher(website);

        if (!matcher.matches()) {
            throw new IllegalArgumentException("The Email Must Be Of The format");
        }
        this.website = website;
    }

    public String getPassword() {
        return password;
    }
    // Validation should include strength-testing
    public void setPassword(String password) {
        
        /*(?=.*[a-z]) The string must contain at least 1 lowercase alphabetical character

         *(?=.*[A-Z]) The string must contain at least 1 uppercase
            alphabetical character

         *(?=.*[0-9]) The string must contain at least 1 numeric character

         *(?=.[!@#\$%\^&]) The string must contain at least one special character, but we are escaping reserved RegEx characters to avoid conflict

         *(?=.{8,}) The string must be eight characters or longer*/
        
        String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\\$%\\^&\\*])(?=.{8,})";

        Pattern pattern = Pattern.compile(regex);

        Matcher matcher = pattern.matcher(password);

        if (!matcher.matches()) {
            throw new IllegalArgumentException("The Password Does Not Meet The Minimum Requarments");
        }
        this.password = password;
    }

    public LocalDateTime getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(LocalDateTime lastUpdated) {
        Manager.lastUpdated = lastUpdated;
    }
    
    public void editAnEntery(String title, String website, String password) {

            setTitle(title);
            setWebsite(website);
            setPassword(password);
            System.out.println("Entery Was Edited");
        
    }
    
    public static void serialization(Object object, String filename)
    {

        // Serialization  
        try
        {
            //Saving of object in a file 
            FileOutputStream file = new FileOutputStream(filename);
            ObjectOutputStream out = new ObjectOutputStream(file);

            // Method for serialization of object 
            out.writeObject(object);

            out.close();
            file.close();

            System.out.println("Object has been serialized");

        }

        catch (IOException ex)
        {
            System.out.println("IOException is caught");
        }

    }

    public void deserialisation(Object object, String filename)
    {

        Object object1 = object;
        // Deserialization 
        try
        {
            // Reading the object from a file 
            FileInputStream file = new FileInputStream(filename);
            ObjectInputStream in = new ObjectInputStream(file);

            // Method for deserialization of object 
            object1 = in.readObject();

            in.close();
            file.close();

        }

        catch (IOException ex)
        {
            System.out.println("IOException is caught");
        }

        catch (ClassNotFoundException ex)
        {
            System.out.println("ClassNotFoundException is caught");
        }
    }

    public static void encrypt(Serializable object, OutputStream ostream) 
    // wrong key and must be encrypted using AES256
    {
        try
        {
            // Length is 16 byte
            SecretKeySpec sks = new SecretKeySpec(key, transformation);

            // Create cipher
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, sks);
            SealedObject sealedObject = new SealedObject(object, cipher);

            // Wrap the output stream
            CipherOutputStream cos = new CipherOutputStream(ostream, cipher);
            ObjectOutputStream outputStream = new ObjectOutputStream(cos);
            outputStream.writeObject(sealedObject);
            outputStream.close();
        }
        catch (IllegalBlockSizeException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static Object decrypt(InputStream istream) 
    {
        SecretKeySpec sks = new SecretKeySpec(key, transformation);
        Cipher cipher = null;
        SealedObject sealedObject = null;
        try {
            cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, sks);

        CipherInputStream cipherInputStream = new CipherInputStream(istream, cipher);
        ObjectInputStream inputStream = new ObjectInputStream(cipherInputStream);
        
        sealedObject = (SealedObject) inputStream.readObject();
         return sealedObject.getObject(cipher);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
          } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        }
       return null;
    }

    @Override
    public String toString() {
        return "Manager{" + "title=" + title + ", website=" + website + ", password=" + password + '}';
    }
    
    
    
    
    
}
