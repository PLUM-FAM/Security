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
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;


public class assignment3 { 

    // Hashes to decrypt (from assignment description)

    public static ArrayList<String> hashesToDecrypt = new ArrayList<String>();
    public static ArrayList<String> dictionaryFiles = new ArrayList<String>();
    public static int dictionaryCount;
    public static double startTime; //program start time
    public static double endTime; 

/*
* Example run command: java assignment3.java <givenHashes file> <dictionary file>
*/
    public static void main(String args[]) throws NoSuchAlgorithmException 
	{ 
        startTime = System.currentTimeMillis();
        importHashes(args[0]);
        // crackstation.txt will crack them all after ~45 mins
        dictionaryFiles.add(args[1]); 

        dictionaryCount = 0;
        while(hashesToDecrypt.size() > 0)
        {
            try
            {
                //System.out.println("--- Using dictionary " + dictionaryFiles.get(dictionaryCount) + "\n");
                useDictionary(dictionaryFiles.get(dictionaryCount));
            }catch(IndexOutOfBoundsException e)
            {
                // exit loop if there are no more dictionary files to use.
                break;
            }
            
        }
    } 

    
    /*
        useDictionary() is separate in case future multithreading is approperate.
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
                    System.out.println("--- Reached the end of the dictionary " + dictionary);
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

			// Static getInstance method is called with hashing MD5 
			MessageDigest md = MessageDigest.getInstance("MD5"); 

            // transfer into bytes
			byte[] messageDigest = md.digest(input.getBytes()); 

			BigInteger no = new BigInteger(1, messageDigest);

			// Convert message digest into hex value 
			String hashtext = no.toString(16); 
            while (hashtext.length() < 32) 
            {   // padding if necessary
				hashtext = "0" + hashtext;  
			} 
			return hashtext; 
        } 
    		catch (NoSuchAlgorithmException e) {throw new RuntimeException(e);} 
	} 
} 
