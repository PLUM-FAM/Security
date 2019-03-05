/*
 * Joel Lechman, John Bemis, Logan Davis
 * 
 * Computer Security Assignment 3
 * Due March 6th 2019
 * 
 * All given hashes are breakable with the crackstation.txt dictionary within ~25 mins
 * Crackstation.txt dictionary can be found at: https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm
 *
 * Example run command: java LechmanBemisDavis.java <givenHashes file.txt> <dictionary file 1.txt> <dictionary file 2.txt>
 */

import java.io.BufferedReader;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 
import java.util.*; 
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;


public class LechmanBemisDavis3 { 
    public static ArrayList<String> hashesToDecrypt = new ArrayList<String>();
    public static ArrayList<String> dictionaryFiles = new ArrayList<String>();
    public static int dictionaryCount = 0; //counter for current dictionary being used. (current index of dictionaryFiles arraylist)
    public static double startTime; //program start time
    public static double endTime;  //holder for end time (used for the breaking of each hash)

    public static void main(String args[]) throws NoSuchAlgorithmException 
	{ 
        startTime = System.currentTimeMillis();
        importHashes(args[0]);//import hashes from file into program.
        dictionaryFiles.add(args[1]);  //import dictionary into program
        //if there are multiple dictionaries given, add there rest.
        int dictCounter =  2;
        while(true)
        {
            try
            {
                dictionaryFiles.add(args[dictCounter]);
                dictCounter++; 
            }catch(ArrayIndexOutOfBoundsException e)
            {
                break;
            }
            
        }

        //while there are still hashes to decrypt, keep trying all dictionaries
        while(hashesToDecrypt.size() > 0)
        {
            try
            {
                useDictionary(dictionaryFiles.get(dictionaryCount));
            }catch(IndexOutOfBoundsException e)
            {
                // exit loop if there are no more dictionary files to use.
                break;
            }
            
        }
    } 

    
    /*
    * useDictionary attempts to break the remaining hashes in the hashesToDecrypt arraylist, once at the end of the dictionary it increments
    * the current dictionary counter and returns void.
    */
    public static void useDictionary(String dictionary)
    {
        BufferedReader fileReader;
        try
        {
            fileReader = new BufferedReader(new FileReader(dictionary));
            String dictionaryEntry;
            String hashOfDictionaryEntry;
            while(true)
            {   
                dictionaryEntry = fileReader.readLine();
                // if we have reached the end of the dictionary, end program.
                if(dictionaryEntry == null)
                {
                    dictionaryCount++;
                    System.out.println("\n --- Reached the end of the dictionary " + dictionary + "\n");
                    break;
                }
                // calculate hash for dictionary entry
                hashOfDictionaryEntry = getMd5(dictionaryEntry); 
                // compare generated hash to arraylist of given hashes we are meant to decrypt.
                if(hashesToDecrypt.contains(hashOfDictionaryEntry))
                {
                    // grab decrypt time (in ms) for the current hash
                    endTime = System.currentTimeMillis() - startTime;
                    // convert to seconds
                    endTime = endTime/Long.valueOf(1000);

                    // if a match, print result
                    // handleResult(hashOfDictionaryEntry, dictionaryEntry, endTime);
                    System.out.println("The password for hash value " + hashOfDictionaryEntry + " is " + dictionaryEntry + ", it takes the program " + endTime +" seconds to recover this password with the " + dictionary + " dictionary");
                    // remove hash from hashesToDecrypt
                    hashesToDecrypt.remove(hashOfDictionaryEntry);
                }

                // if we have decrypted all of the given hashes then end program
                if((hashesToDecrypt.size() < 1))
                {
                    break;
                }
            }
            fileReader.close();
        }catch(IOException e){System.out.println("file read error");}
    }

    // import hashes from a text file to decrypt.
    public static void importHashes(String fileName)
    {
        try{
            BufferedReader fileReader2 = new BufferedReader(new FileReader(fileName));
            while(true)
            {
                String passwordHashed = fileReader2.readLine();
                if(passwordHashed != null)
                {
                    hashesToDecrypt.add(passwordHashed);
                }else{
                    break;
                }
            }
        }catch(IOException e){}
    }

    // Java program to calculate MD5 hash value 
	public static String getMd5(String input) 
	{ 
		try { 

			//Instance of MessageDigest for MD5
			MessageDigest md = MessageDigest.getInstance("MD5"); 

            //transfer into bytes
			byte[] messageDigest = md.digest(input.getBytes()); 
            //into integer
			BigInteger no = new BigInteger(1, messageDigest);

			// Convert message digest into hex value 
			String hashtext = no.toString(16); 
            while (hashtext.length() < 32) 
            {   // padding the hash if necessary (not applicable for this assignment but could be possible for really short passwords.)
				hashtext = "0" + hashtext;  
			} 
			return hashtext; 
        } 
    		catch (NoSuchAlgorithmException e) {throw new RuntimeException(e);} 
	} 
} 
