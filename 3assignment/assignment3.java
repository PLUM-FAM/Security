/*
NOTES:
2 of the 6 are all digits  breakable with dictionary : digits 1-99999999
(QINGFANG & wakemeupwhenseptemberends & 181003) are breakable with crackstation-human-only.txt
victorboy and lion8888 QINGFANG wakemeupwhenseptemberends

*/ 

import java.io.BufferedReader;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 
import java.util.*; 
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;


public class assignment3 { 

    //Hashes to decrypt (from assignment description)

    public static ArrayList<String> hashesToDecrypt = new ArrayList<String>();
    public static ArrayList<String> dictionaryFiles = new ArrayList<String>();
    public static int dictionaryCount;
    public static double startTime; //program start time
    public static double endTime; 

	public static void main(String args[]) throws NoSuchAlgorithmException 
	{ 
        startTime = System.currentTimeMillis();
        hashesToDecrypt.add("6f047ccaa1ed3e8e05cde1c7ebc7d958");
        hashesToDecrypt.add("275a5602cd91a468a0e10c226a03a39c");
        hashesToDecrypt.add("b4ba93170358df216e8648734ac2d539");
        hashesToDecrypt.add("dc1c6ca00763a1821c5af993e0b6f60a");
        hashesToDecrypt.add("8cd9f1b962128bd3d3ede2f5f101f4fc");
        hashesToDecrypt.add("554532464e066aba23aee72b95f18ba2");

        //dictionaryFile.add(args[0]);

        //dictionaryFiles.add("digits1-99999999.txt");
        //dictionaryFiles.add("crackstation-human-only.txt");
        dictionaryFiles.add("crackstation.txt");
        //dictionaryFiles.add("probable-top12000.txt");
        //dictionaryFiles.add("darkweb2017-top10000.txt"); //not working - need to change filereader
        

        dictionaryCount = 0;
        System.out.println(dictionaryFiles.size() + " # txt files loaded");
        while(hashesToDecrypt.size() > 0)
        {
            try
            {
                System.out.println("--- Using dictionary " + dictionaryFiles.get(dictionaryCount));
                useDictionary(dictionaryFiles.get(dictionaryCount));
            }catch(IndexOutOfBoundsException e)
            {
                //exit loop if there are no more dictionary files to use.
                break;
            }
            
        }
        System.out.println("\n*** Program done ***\n");

    } 

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
                dictionaryEntry = fileReader.readLine(); //***** Doesnt read some files
                //if we have reached the end of the dictionary, end program.
                if(dictionaryEntry == null)
                {
                    dictionaryCount++;
                    System.out.println("--- Reached the end of the dictionary " + dictionary);
                    break;
                }

                hashOfDictionaryEntry = getMd5(dictionaryEntry); //calculate hash for dictionary entry

                //System.out.println("Calculated hash for entry: " + dictionaryEntry + " is: " + hashOfDictionaryEntry);

                //compare generated hash to arraylist of given hashes we are meant to decrypt.
                if(hashesToDecrypt.contains(hashOfDictionaryEntry))
                {
                    //grab decrypt time (in ms) for the current hash
                    endTime = System.currentTimeMillis() - startTime;
                    //convert to seconds
                    endTime = endTime/Long.valueOf(1000);

                    //if a match, print result
                    handleResult(hashOfDictionaryEntry, dictionaryEntry, endTime);
                    System.out.println("The password for hash value " + hashOfDictionaryEntry + " is " + dictionaryEntry + ", it takes the program " + endTime +" seconds to recover this password with the " + dictionary + " dictionary");
                    //remove hash from hashesToDecrypt
                    hashesToDecrypt.remove(hashOfDictionaryEntry);
                }

                //if we have decrypted all of the given hashes then end program
                if((hashesToDecrypt.size() < 1))
                {
                    break;
                }
            }
            fileReader.close();
        }catch(IOException e){System.out.println("file read error");}
    }
    
    // Java program to calculate MD5 hash value 
	public static String getMd5(String input) 
	{ 
		try { 

			// Static getInstance method is called with hashing MD5 
			MessageDigest md = MessageDigest.getInstance("MD5"); 

			// digest() method is called to calculate message digest 
			// of an input digest() return array of byte 
			byte[] messageDigest = md.digest(input.getBytes()); 

			// Convert byte array into signum representation 
			BigInteger no = new BigInteger(1, messageDigest); 

			// Convert message digest into hex value 
			String hashtext = no.toString(16); 
			while (hashtext.length() < 32) { 
				hashtext = "0" + hashtext; 
			} 
			return hashtext; 
        } 
    		catch (NoSuchAlgorithmException e) { 
			throw new RuntimeException(e); 
		} 
	} 
} 
