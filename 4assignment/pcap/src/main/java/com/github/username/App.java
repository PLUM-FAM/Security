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

    static PcapNetworkInterface getNetworkDevice() 
    {
        PcapNetworkInterface device = null;
        try 
        {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;    }

    public static void main(String[] args) 
    {
        System.out.println("Main start");
        
        PcapHandle handle;

        //final PcapIpV4Address handleAddress;
        try 
        {
            handle = Pcaps.openOffline("lbl-internal.20041004-1305.port002.dump.pcap", TimestampPrecision.NANO);
            //handle = Pcaps.openOffline("attack1.pcapng", TimestampPrecision.NANO);

            // //Filtering of packets using BPF filter.
            try{
                String filter = "tcp && portrange 1-65535";//& tcp-ack|tcp-syn"; //"tcp port 80";
                handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
            } catch(NotOpenException e1)
            {
                System.out.println("Not open exception error");
            }
            


            PacketListener listener = new PacketListener() 
            {
                int count = 0;

                @Override
                public void gotPacket(Packet packet) 
                {
                    // Override the default gotPacket() function and process packet
                    System.out.println(handle.getTimestamp());
                    System.out.println(packet);
                    // byte[] header = packet.getRawData();
                    // System.out.println("Header: " + packet.getHeader());
                    // System.out.println("Payload: " + packet.getPayload());
                    try{
                        System.out.println("COUNT " + count);
                        
                        byte[] rawPacketEx = packet.getRawData();
                        // System.out.println("RAW " + rawPacketEx);

                        EthernetPacket ethPckt = EthernetPacket.newPacket(rawPacketEx, 0, rawPacketEx.length);
                        System.out.println("ETH " + ethPckt);
                        
                        // byte[] ethByteArray = ethPckt.getPayload().getRawData();
                        // Dot1qVlanTagPacket dotPckt = Dot1qVlanTagPacket.newPacket(ethByteArray, 0, ethByteArray.length);
                        // System.out.println("DotPckt: " + dotPckt);
                        // System.out.println(typeOf(ethPckt.getPayload()));
                        
                        // System.out.println("Assertion " + ethPckt.contains(IpV4Packet.class));
                        System.out.println("------------------------------");
                        if(ethPckt.getPayload().contains(IpV4Packet.class))
                        {
                            System.out.println("IpV4*");
                        }  
                        if(ethPckt.getPayload().contains(IpV6Packet.class))
                        {
                            System.out.println("IpV6");
                        }
                        if(ethPckt.contains(EthernetPacket.class))
                        {
                            System.out.println("Ethernet");
                        }else{System.out.println("Not Ethernet");}
                        if(ethPckt.contains(GtpV1Packet.class))
                        {
                            System.out.println("GtpV1");
                        }
                        if(ethPckt.contains(HdlcPppPacket.class))
                        {
                            System.out.println("HdlcPpp");
                        }
                        if(ethPckt.contains(IcmpV4EchoPacket.class))
                        {
                            System.out.println("Icmpv4Echo");
                        }
                        if(ethPckt.contains(IcmpV4EchoReplyPacket.class))
                        {
                            System.out.println("IcmpV4EchoReply");
                        }
                        if(ethPckt.contains(IcmpV4InformationReplyPacket.class))
                        {
                            System.out.println("IcmpV4InformationReply");
                        }
                        if(ethPckt.contains(IcmpV4InformationRequestPacket.class))
                        {
                            System.out.println("IcmpV4InformationRequest");
                        }
                        if(ethPckt.contains(IcmpV4ParameterProblemPacket.class))
                        {
                            System.out.println("IcmpV4ParameterProblem");
                        }
                        if(ethPckt.contains(IcmpV4RedirectPacket.class))
                        {
                            System.out.println("IcmpV4Redirect");
                        }
                        System.out.println("END conditionals________");

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

                        System.out.println("Destination Address: " + packet.get(IpV4Packet.class).getHeader().getDstAddr());
                        
                    }//catch (PcapNativeException e){}
                    //catch (EOFException e){}
                    //catch (TimeoutException e ){}
                    //catch (NotOpenException e ){}
                    catch (IllegalRawDataException e){}
                }
            };

            // Tell the handle to loop using the listener we created
            try 
            {
                int maxPackets = 1000;
                handle.loop(maxPackets, listener);
                System.out.println("HANDLE: " + handle);
            }catch (InterruptedException e){}
            catch(NotOpenException e){}

            // Cleanup when complete
            handle.close();


        } catch (PcapNativeException e) 
        {
            System.out.println("Caught pcapnative exception");
            //handle = Pcaps.openOffline("dump.pcap");
        }
        


        

        System.out.println("Main end");
    }
}