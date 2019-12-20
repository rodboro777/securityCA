/*
 * Name: Yahya Angawi
 * Student ID: D00233709
 ** 
 */
package passwordmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main implements Serializable {
    // to fix ocal class incompatible: stream classdesc serialVersionUID different error

    private static final long serialVersionUID = 1L;
    private static ArrayList<Manager> mangList;
    private static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) {

        Manager mang = null;
        boolean enter = true;
        File f = new File("./user.txt");

        if (f.exists()) {
            enter = verifyPassword();
        } else {
            storeUserPassword();
        }
        
        boolean exit = false;
        menu();

        while (exit == false && (enter == true)) {
            try {
                menu();
                System.out.print("\nChoose From The Menu: (17 to show available Options)> ");
                int action = sc.nextInt();
                sc.nextLine();

                switch (action) {
                    case 0:
                        System.out.println("Shutting down, Goodbye");
                        exit = true;
                        break;

                    case 1:
                        // create entries
                        mang = createEntry();
                        mangList.add(mang);

                        break;

                    case 2:
                        // edit entries
                        System.out.println("Please Enter The Entery's ID: ");
                        int enteryid = sc.nextInt();
                        mang = findEntery(enteryid);
                        System.out.println("Please Enter The Title: ");
                        String title = sc.next();
                        System.out.println("Please Enter The website: ");
                        String website = sc.next();
                        System.out.println("Please Enter The Desired password: ");
                        String password = sc.next();
                        mang.editAnEntery(title, website, password);
                        System.out.println("Entery Was Editted");
                        break;
                    case 3:
                        // view an entry
                        System.out.println("Please Enter The Entery's ID: ");
                        enteryid = sc.nextInt();
                        mang = findEntery(enteryid);
                        System.out.println(mang.toString());

                        break;
                    case 4:
                        // view all entries
                        displayAllEnteries();
                        break;
                    case 5:
                        // change their master password
                        System.out.println("Please Enter The Entery's ID: ");
                        enteryid = sc.nextInt();
                        mang = findEntery(enteryid);
                        System.out.println("Please The New Password: ");
                        password = sc.nextLine();
                        mang.setPassword(password);
                        break;
                    case 6:
                        // delete entries
                        System.out.println("Please Enter The Entery's ID That You Want To Delete: ");
                        enteryid = sc.nextInt();
                        mang = findEntery(enteryid);
                        mangList.remove(mang);
                        System.out.println("Entery is Removed");
                        break;
                }
            } catch (Exception e) {
                System.out.println("Wrong Input!");
                sc.next();
                continue;
            }
        }
    }

    private static void menu() {
        System.out.println("\nAvailable options:\npress");
        System.out.println("0 - to shutdown\n"
                + "1 - To Create An Entry\n"
                + "2 - To Edit An Entry\n"
                + "3 - To view An Entry\n"
                + "4 - To view All Entries\n"
                + "5 - To change their master password\n"
                + "6 - To Remove An Entry\n");
    }

    public static boolean verifyPassword() {
        boolean pass = false;
        File f = new File("./user.txt");
        try {

            if (f.exists()) {
                // Ask user to input a password
                System.out.println("Please enter your password:");

                Scanner keyboard = new Scanner(System.in);
                String plaintextPassword = keyboard.nextLine();
                // Read the stored password hash and config data
                Scanner in = new Scanner(new FileReader(f));
                String salt = in.nextLine();
                String hash = in.nextLine();

                // Create a password object from the file contents
                Password password = new Password(plaintextPassword, salt);

                // Check the entered password matches the stored password hash
                if (password.matchesHash(hash)) {
                    pass = true;
                    System.out.println("Correct password, Access Granted!");
                } else {
                    pass = limitAttempts();
                    System.out.println("Wrong password, Access Denied!");
                }
                in.close();
            }

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return pass;
    }

    public static void storeUserPassword() {

        File f = new File("./user.txt");
        try {

            // Ask user to input a password
            System.out.println("Please enter Perfered New password: ");

            Scanner keyboard = new Scanner(System.in);
            String plaintextPassword = keyboard.nextLine();
            String passwordSalt = Password.generateRandomSalt();

            // Hash the user password
            Password password = new Password(plaintextPassword, passwordSalt);
            String hash = password.generateHash();

            FileWriter out = new FileWriter(f);

            // Write the hash and Salt for later validation to a file
            out.write(password.getSalt() + "\n");
            out.write(hash);
            out.close();
            System.out.println("Password hash saved to file");

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Manager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static Manager createEntry() {

        Manager m = null;
        try {
            System.out.println("Would You Like To Enter A Title For This Entery (Y Or N): ");
            String yes = sc.next();
            if (yes.equalsIgnoreCase("Y")) {

                System.out.println("Please Enter The Title: ");
                String title = sc.next();
                System.out.println("Please Enter The website: ");
                String website = sc.next();
                System.out.println("Please Enter The Desired password: ");
                String password = sc.next();

                System.out.println("Entery Was Created");

                m = new Manager(title, website, password);

            } else if (yes.equalsIgnoreCase("N")) {

                System.out.println("Please Enter The website: ");
                String website = sc.next();
                System.out.println("Please Enter The Desired password: ");
                String password = sc.next();

                System.out.println("Entery Was Created");

                m = new Manager(website, password);

            } else {
                System.out.println("Wrong Input!");
            }

        } catch (Exception e) {
            System.out.println("There Was A Wrong Input!");
        }

        return m;
    }

    private static Manager findEntery(int id) {

        for (int i = 0; i < mangList.size(); i++) {
            if (mangList.get(i).getId() == id) {
                return mangList.get(i);
            }
        }
        System.out.println("Entery With id = " + id + " Does Not Exist");
        return null;

    }

    public static void displayAllEnteries() {

        for (Manager m : mangList) {
            System.out.println(m.toString());
        }
    }

    // exponential backoff
    public static boolean limitAttempts() {

        int attempts = 0;
        int quitWhenAttempts = 2;
        long lastAttemptTime = unixTime();
        boolean access = false;
        File f = new File("./user.txt");

        // Loop will run until 6 attempts have been made
        while ((attempts < quitWhenAttempts) && access == false) {
            
            long currentTime = unixTime();
            long timeoutSeconds = calculateTimeoutSeconds(attempts);
            long nextAttemptTime = lastAttemptTime + timeoutSeconds;
            int attemted = quitWhenAttempts+1;
            
            if ((currentTime >= nextAttemptTime)) {
                System.out.println("Number Of Attempt Allowed " + attemted);
                System.out.println("Allowed an attempt at " + currentTime);
                System.out.println("Please enter your password: ");

                Scanner keyboard = new Scanner(System.in);
                String plaintextPassword = keyboard.nextLine();
                // Read the stored password hash and config data
                Scanner in;
                try {
                    in = new Scanner(new FileReader(f));
                    String salt = in.nextLine();
                String hash = in.nextLine();
                // Create a password object from the file contents
                Password password = new Password(plaintextPassword, salt);

                // Check the entered password matches the stored password hash
                if (password.matchesHash(hash)) {
                    access = true;
                    System.out.println("Correct password, Access Granted!");
                    break;
                }
                
                attempts ++;
                lastAttemptTime = currentTime;
                attemted--;
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
        }
        return access;
    }

    // #######################################################
    // # Time Utility
    // #######################################################
    /**
     * Returns the number of seconds that have passed since midnight on Jan 01st
     * 1970 (Unix Epoch)
     */
    public static long unixTime() {
        return System.currentTimeMillis() / 1000L;
    }

    // #######################################################
    // # Exponential Backoff Utility
    // #######################################################
    /**
     * Returns the number of seconds a timeout should be if {attempts} attempts
     * have already been made Timeout is returned in seconds, calculated as
     * 2^(attempts - 1) 1 attempt = 0s timeout 2 attempts = 2s timeout 3
     * attempts = 4s timeout 4 attempts = 8s timeout etc. If attempts is <= 0, 0
     * is returned
     */
    public static long calculateTimeoutSeconds(int attempts) {
        return attempts > 0
                ? (long) Math.pow(2, (attempts - 1))
                : 0;
    }

}
