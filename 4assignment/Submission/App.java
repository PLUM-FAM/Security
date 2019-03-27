
/*
 *  Joel Lechman, John Bemis, Logan Davis
 *  Security Assignment 4
 *  Due March 27th 2019
 * 
 *  We used the pcap4j library as we do not use Netbeans and the documentation site for
 *  the provided netbeans library was down.
 * 
 *  Please contact us with any questions regarding running our program or how it works.
 *  We are happy to come and demo or make a video demoing our program.
 * 
 *  Also please check out our submission notes on D2L.
 */



 //Run instructions.
//   mvn package
//   java -jar target/uber-pcap-1.0.0.jar

package com.github.username;

import java.io.IOException;
import java.util.*;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.Pcaps;
import java.sql.Timestamp;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.PcapIpV4Address;
import com.sun.jna.Platform;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.IcmpV4CommonPacket;
import java.net.Inet4Address;
import org.pcap4j.packet.IpV4Packet;
import java.io.EOFException;
import java.util.concurrent.TimeoutException;

import javax.print.attribute.standard.Destination;

import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.GtpV1Packet;
import org.pcap4j.packet.HdlcPppPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV4InformationReplyPacket;
import org.pcap4j.packet.IcmpV4InformationRequestPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4RedirectPacket;




public class App 
{

    static ArrayList<String> SourceArrayList = new ArrayList<String>();
    static ArrayList<String> DestinationArrayList = new ArrayList<String>();

    static PcapNetworkInterface getNetworkDevice() 
    {
        PcapNetworkInterface device = null;
        try 
        {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;    
    }

    public static void main(String[] args) 
    {
        PcapHandle handle; //declare the pcap handle
        try 
        {
            //initialize the handle for the input file and nano timestamp precision (recommended on lib documantation)
            //handle = Pcaps.openOffline("lbl-internal.20041004-1305.port002.dump.pcap", TimestampPrecision.NANO);
            handle = Pcaps.openOffline(args[0], TimestampPrecision.NANO);
            // //Filtering of packets using BPF filter.
            try{
                String filter ="tcp && portrange 1-65535";//& tcp-ack|tcp-syn"; //"tcp port 80";
                handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
            } 
            catch(NotOpenException e1)
            {
                System.out.println("Not open exception error");
            }
            


            PacketListener listener = new PacketListener() 
            {
                @Override
                public void gotPacket(Packet packet) 
                {
                    // Override the default gotPacket() function and process packet
                    try{                        
                        byte[] rawPacketEx = packet.getRawData();
                        EthernetPacket ethPckt = EthernetPacket.newPacket(rawPacketEx, 0, rawPacketEx.length);                        
                        String destination = ethPckt.getHeader().getDstAddr().toString();
                        String source = ethPckt.getHeader().getSrcAddr().toString();
                        SourceArrayList.add(source);
                        DestinationArrayList.add(destination);
                                                
                        
                        /*-------------------------------------------------------*/
                        // The commented code below shows how we approached      |
                        // getting the IpV4 source and destination addresses.    |
                        // We tried converting an ethernet packet to a           |
                        // Dot1qVlanTagPacket, then converting that to an        |
                        // IpV4 packet, and finally converting that to a TCP     |
                        // packet, and receiving the source and destination      |
                        // addresses from that. We were never able to convert to |
                        // an IpV4 packet for some reason, and everything we     |
                        // found online suggested that the way we did it should  |
                        // work.                                                 |
                        /*-------------------------------------------------------*/

                        // byte[] ethByteArray = ethPckt.getPayload().getRawData();
                        // Dot1qVlanTagPacket dotPckt = Dot1qVlanTagPacket.newPacket(ethByteArray, 0, ethByteArray.length);
                        // System.out.println("DotPckt: " + dotPckt);
                        // System.out.println(typeOf(ethPckt.getPayload()));
                        
                        // System.out.println("Assertion " + ethPckt.contains(IpV4Packet.class));

                        // IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                        // assertNotNull(ipV4Packet);
                        // IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
                        // assertNotNull(ipV4Header);

                        // byte[] ipv4ByteArray = ethPckt.getPayload().getRawData();
                        // System.out.println(ipv4ByteArray.toString());
                        // IpV4Packet ipv4Pckt = IpV4Packet.newPacket(ipv4ByteArray, 0, rawPacketEx.length);
                        // System.out.println("IpV4Packet: " + ipv4Pckt);
                        

                        // byte[] tcpByteArray = ipv4Pckt.getPayload().getRawData();
                        // TcpPacket tcp = TcpPacket.newPacket(tcpByteArray, 0, 14);
                        // System.out.println("Tcp: " + tcp);

                        //System.out.println("Destination Address:--- " + packet.get(IpV4Packet.class).getHeader().getDstAddr());
                        
                    }
                    //catch (PcapNativeException e){}
                    //catch (EOFException e){}
                    //catch (TimeoutException e ){}
                    //catch (NotOpenException e ){}
                    catch (IllegalRawDataException e){}
                }
            };

            // Tell the handle to loop using the listener (so that we can access gotPacket() method.)
            try 
            {
                int maxPackets = 100000;

                handle.loop(maxPackets, listener);
                findOccurrences(SourceArrayList, DestinationArrayList);
            }
            catch (InterruptedException e){}
            catch(NotOpenException e){}

            // Cleanup when complete
            handle.close();

        } catch (PcapNativeException e) 
        {
            System.out.println("Caught pcapnative exception");
            //handle = Pcaps.openOffline("dump.pcap");
        }
    }

    //method to find the unique occurances for each entry in sources and destinations. also counts the
    //number of occurances per unique entry and calls the print method for the desired output.
    public static void findOccurrences(ArrayList<String> sources, ArrayList<String> destinations)
    {
        String [][] SourceAddressArray = new String[1][2];
        String sourceAddress1 = sources.get(0);
        int length;

        //grab the first occurance and compare with other occurances in list, then loop through them all again to get counts for each unique occurance

        for(int i = 0; i < sources.size() - 1; i++)
        {
            if(sources.get(i) == sourceAddress1 && !searchArray(sourceAddress1, SourceAddressArray))
            {
                SourceAddressArray[SourceAddressArray.length - 1][0] = sourceAddress1;
                SourceAddressArray[SourceAddressArray.length - 1][1] += 'i';
                length = SourceAddressArray.length;
                for(int j = 0; j < length; j++)
                {
                    SourceAddressArray[j] = Arrays.copyOf(SourceAddressArray[j], SourceAddressArray[j].length + 1);
                }
            }
            else if(sources.get(i) == sourceAddress1)
            {
                SourceAddressArray[0][1] += 1;
            }
            else if(sources.get(i) != sourceAddress1 && !searchArray(sources.get(i), SourceAddressArray))
            {
                SourceAddressArray[SourceAddressArray.length - 1][0] = sources.get(i);
                SourceAddressArray[SourceAddressArray.length - 1][1] += 'i';
                length = SourceAddressArray.length;
                for(int j = 0; j < length; j++)
                {
                    SourceAddressArray[j] = Arrays.copyOf(SourceAddressArray[j], SourceAddressArray[j].length + 1);
                }
            }
        }

        for(int i = 1; i < SourceAddressArray.length - 2; i++)
        {
            String sourceAddress = SourceAddressArray[i][1];

            for(int j = 0; j < sources.size() - 1; j++)
            {
                if(sources.get(j) == sourceAddress)
                {
                    SourceAddressArray[i][1] += 'i';
                }
            }
        }
        
        //doing the same for destinations
        String [][] DestinationAddressArray = new String[1][2];
        String destinationAddress1 = destinations.get(0);
        for(int i = 0; i < destinations.size() - 1; i++)
        {
            if(destinations.get(i) == destinationAddress1 && !searchArray(destinationAddress1, DestinationAddressArray))
            {
                DestinationAddressArray[DestinationAddressArray.length - 1][0] = destinationAddress1;
                DestinationAddressArray[DestinationAddressArray.length - 1][1] += 'i';
                length = DestinationAddressArray.length;
                for(int j = 0; j < length; j++)
                {
                    DestinationAddressArray[j] = Arrays.copyOf(DestinationAddressArray[j], DestinationAddressArray[j].length + 1);
                }
                
            }
            else if(destinations.get(i) == destinationAddress1)
            {
                DestinationAddressArray[0][1] += 1;
            }
            else if(destinations.get(i) != destinationAddress1 && !searchArray(destinations.get(i), DestinationAddressArray))
            {
                DestinationAddressArray[DestinationAddressArray.length - 1][0] = destinations.get(i);
                DestinationAddressArray[DestinationAddressArray.length - 1][1] += 'i';
                length = DestinationAddressArray.length;
                for(int j = 0; j < length; j++)
                {
                    DestinationAddressArray[j] = Arrays.copyOf(DestinationAddressArray[j], DestinationAddressArray[j].length + 1);
                }
            }
        }

        for(int i = 1; i < DestinationAddressArray.length - 2; i++)
        {
            String destinationAddress = DestinationAddressArray[i][1];

            for(int j = 0; j < destinations.size() - 1; j++)
            {
                if(destinations.get(j) == destinationAddress)
                {
                    DestinationAddressArray[i][1] += 'i';
                }
            }
        }
        printOccurrences(SourceAddressArray, DestinationAddressArray);
    }

    // takes in 2d arrays and then prints the source addresses that have 3x more count then the destinations.
    public static void printOccurrences(String[][] sources, String[][] destinations)
    {
        for(int i = 0; i < sources.length; i++)
        {
            for(int j = 0; j < destinations.length; j++)
            {
                String sourceCompare = sources[i][1];
                String destinationCompare = destinations[j][1];
                if(sources[i][0] == destinations[j][0] && sourceCompare.length() >= 3 * destinationCompare.length())
                {
                    System.out.println(sources[i][0]);
                }else{
                    System.out.println(sources[i][0]);
                    System.out.println(destinations[i][0]);
                }
            }
        }
    }
    
    //Searches the 2D string array passed in for the passed in string s. Returns True if s is found in the array.
    public static Boolean searchArray(String s, String[][] array)
    {
        for(int i = 0; i < array.length -1; i++)
        {
            if(s == array[i][0])
            {
                return true;
            }
        } 
        return false;
    }
}