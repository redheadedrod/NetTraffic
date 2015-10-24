package nettraffic;
import java.util.Date;
import org.jnetpcap.*;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.util.PcapPacketArrayList;

public class ProcessPacket {
    // Number of records to read in
    private static int records = 500;
    // array list of packets
    private PcapPacketArrayList packets;

    // empty constructor
    public ProcessPacket() {
        String file = "C:\\Users\\Rodney\\SkyDrive\\School\\CIS 457 Datacom\\NetTraffic\\src\\nettraffic\\sample.pcap";
        this.packets = ProcessFile(file);
    }

    // constructor with filename
    public ProcessPacket(String file) {
        this.packets = ProcessFile(file);
    }

    /**
     * This function will read the packet from the offline file and load it into a PcapPacketArraylist
     * for further processing. taken from tutorials
     * @param file - filename of the file to use - Will default to the sample file but will otherwise read it from
     *             command line
     * @return  - returns an array list containing the records
     */
    private PcapPacketArrayList ProcessFile(String file) {
        /***************************************************************************
         * First we setup error buffer
         **************************************************************************/
        StringBuilder errbuf = new StringBuilder(); // For any error msgs
        System.out.printf("Opening file for reading: %s%n", file);
        /***************************************************************************
         * Second we open up the selected file using openOffline call
         **************************************************************************/
        Pcap pcap = Pcap.openOffline(file, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return null;
        }
        /***************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop.
         **************************************************************************/
        PcapPacketHandler<PcapPacketArrayList> jpacketHandler = new PcapPacketHandler<PcapPacketArrayList>() {
            public void nextPacket(PcapPacket packet, PcapPacketArrayList PaketsList) {
                PaketsList.add(packet);
            }
        };
        /***************************************************************************
         * Fourth we enter the loop and tell it to capture 10 packets. The loop
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
         * is needed by JScanner. The scanner scans the packet buffer and decodes
         * the headers. The mapping is done automatically, although a variation on
         * the loop method exists that allows the programmer to sepecify exactly
         * which protocol ID to use as the data link type for this pcap interface.
         **************************************************************************/
        try {
            PcapPacketArrayList packets = new PcapPacketArrayList();
            pcap.loop(records, jpacketHandler, packets );
            return packets;
        } finally {
            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        }

    }

    public int length() {
        return this.packets.size();
    }

    public void ethernetIIPackets() {
        //stub
    }

}
