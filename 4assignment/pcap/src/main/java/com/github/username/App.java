// App.java

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
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapStat;
import com.sun.jna.Platform;
import org.pcap4j.core.BpfProgram.BpfCompileMode;





public class App {

    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    public static void main(String[] args) {
        System.out.println("Main start");
        final PcapHandle handle;
        try {
            handle = Pcaps.openOffline("smallFlows.pcap", TimestampPrecision.NANO);
            try{
                String filter = "tcp port 80";
                handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
            } catch(NotOpenException e1)
            {
                System.out.println("Not open exception error");
            }
            


            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    // Override the default gotPacket() function and process packet
                    System.out.println(handle.getTimestamp());
                    System.out.println(packet);
                }
            };
            // Tell the handle to loop using the listener we created
            try {
                int maxPackets = 50;
                handle.loop(maxPackets, listener);
            } 
            catch (InterruptedException e2){}
            catch(NotOpenException enotopen){}
                

            // Cleanup when complete
            handle.close();


        } catch (PcapNativeException e) {
            System.out.println("Caught pcapnative exception");
            //handle = Pcaps.openOffline("dump.pcap");
        }
        


        

        System.out.println("Main end");
    }
}