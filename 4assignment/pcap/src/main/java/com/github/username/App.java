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
        final PcapHandle handle;
        //final PcapIpV4Address handleAddress;
        try 
        {
            handle = Pcaps.openOffline("lbl-internal.20041004-1305.port002.dump.pcap", TimestampPrecision.NANO);

            // Filtering of packets using BPF filter.
            // try{
            //     String filter = ""; //"tcp port 80";
            //     handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
            // } catch(NotOpenException e1)
            // {
            //     System.out.println("Not open exception error");
            // }
            


            PacketListener listener = new PacketListener() 
            {
                @Override
                public void gotPacket(Packet packet) 
                {
                    // Override the default gotPacket() function and process packet
                    System.out.println(handle.getTimestamp());
                    System.out.println(packet);
                    // System.out.println("Header: " + packet.getHeader());
                    // System.out.println("Payload: " + packet.getPayload());
                    try{
                        byte[] rawPacketEx = handle.getNextRawPacketEx();
                        System.out.println("RAW " + rawPacketEx);

                        EthernetPacket ethPckt = EthernetPacket.newPacket(rawPacketEx, 0, rawPacketEx.length);
                        System.out.println("ETH " + ethPckt);
                        System.out.println("ETH header" + ethPckt.getHeader());
                        
                        // byte[] ethByteArray = ethPckt.getPayload().getRawData();
                        // Dot1qVlanTagPacket dotPckt = Dot1qVlanTagPacket.newPacket(ethByteArray, 0, ethByteArray.length);
                        // System.out.println("DotPckt: " + dotPckt);
                        //System.out.println(typeOf(ethPckt.getPayload()));
                        
                        byte[] ipv4ByteArray = ethPckt.getPayload().getRawData();
                        IpV4Packet ipv4Pckt = IpV4Packet.newPacket(ipv4ByteArray, 0, ipv4ByteArray.length);
                        System.out.println("IpV4Packet: " + ipv4Pckt);

                        byte[] tcpByteArray = ipv4Pckt.getPayload().getRawData();
                        TcpPacket tcp = TcpPacket.newPacket(tcpByteArray, 0, 14);
                        System.out.println("Tcp: " + tcp);

                        System.out.println("Destination Address: " + packet.get(IpV4Packet.class).getHeader().getDstAddr());
                    }catch (PcapNativeException e){}
                    catch (EOFException e){}
                    catch (TimeoutException e ){}
                    catch (NotOpenException e ){}
                    catch (IllegalRawDataException e){}
                    
                    // PcapIpV4Address ip = new PcapIpV4Address("test")                    
                }
            };

            // Tell the handle to loop using the listener we created
            try 
            {
                int maxPackets = 10000;
                handle.loop(maxPackets, listener);
                System.out.println("HANDLE: " + handle);
            } catch (InterruptedException e){}
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