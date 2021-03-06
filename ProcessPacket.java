/**
 * Project 3 for CIS 457
 * Rodney Fulk
 * Laura Young
 */
package nettraffic;
import java.util.ArrayList;
import java.util.Arrays;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.util.PcapPacketArrayList;
import java.io.File;

public class ProcessPacket {
    // Number of records to read in
    private static int records = 500;
    // array list of packets
    private PcapPacketArrayList packets;

    // empty constructor
    public ProcessPacket() {
        //String file = "C:\\Users\\Rodney\\SkyDrive\\School\\CIS 457 Datacom\\NetTraffic\\src\\nettraffic\\sample.pcap";
        String file = ".\\src\\nettraffic\\sample.pcap";
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
        // to get current directory for error statement
        File dir = new File("");
        /***************************************************************************
         * Second we open up the selected file using openOffline call
         **************************************************************************/
        Pcap pcap = Pcap.openOffline(file, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString() + "\n(Current directory is : "+dir.getAbsolutePath()+")");
            System.exit(1);
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
            PcapPacketArrayList loadPackets = new PcapPacketArrayList();
            pcap.loop(records, jpacketHandler, loadPackets );
            return loadPackets;
        } finally {
            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        }

    }

    /**
     * Returns the length of the packets array list
     * @return
     */
    public int length() {
        return this.packets.size();
    }

    /**
     * Checks for the address pair of source and destination to be the same
     * @param pair  - Address looking up
     * @param pairs - array list of all unique address pairs
     * @return - return position in pairs that pair resides in or a -1 if no match
     */
    public int checkAddresses(IPV4AddressPairs pair, ArrayList<IPV4AddressPairs> pairs) {
        for (int i = 0; i < pairs.size(); i++)
            if (Arrays.equals(pair.getSrce(), pairs.get(i).getSrce()) &&
                    Arrays.equals(pair.getDest(), pairs.get(i).getDest())) return i;
            return -1;
    }

    /**
     * Deals with ipv4 packets.
     * Used to accomplish item 4 but could also be modified for #5 and more
     */
    public void ipv4PacketAddresses() {
        // holds packet we are looking at
        PcapPacket tempPacket;
        // holds the pair we are looking at
        IPV4AddressPairs tempPair;
        // initialize our values
        int temp, ipv4 = 0;
        float percent;
        // setup an array list to hold our pair and the count of how many pairs there are
        ArrayList<IPV4AddressPairs> pairs = new ArrayList<IPV4AddressPairs>();
        // hold packet type
        int tipe;
        // hold destination address
        byte[] dest;
        // hold source address
        byte[] srce;
        // itterate through all records
        for (int i = 0; i < records; i++) {
            tempPacket = packets.get(i);
            tipe = tempPacket.getUShort(12);
            //type 0x0800 are ipv4 0x086dd are ipv6
            if (tipe == 0x0800) {
                ipv4++;
                srce = tempPacket.getByteArray(0x001A, 4);
                dest = tempPacket.getByteArray(0x001E, 4);
                tempPair = new IPV4AddressPairs(srce, dest);
                //System.out.printf("%d Record = %s\n", i + 1, tempPair.toString()); // remove when done
                // checks if tempPair exists in pairs already
                temp = checkAddresses(tempPair, pairs);
                if (temp != -1) {
                    //System.out.println("Matching pair!"); // remove when done
                    pairs.get(temp).incCnt();
                    //System.out.printf("%d Record = %s\n", i + 1, pairs.get(temp).toString());  // remove when done
                }
                else
                    // apparently not already in the list to lets add it
                    pairs.add(tempPair);
            }
        }
        System.out.printf("\nOut of %d records %d were Ethernet II/IPV4 and of those IPV4 records the following %d address pairs\n", records, ipv4, pairs.size());
        System.out.println("each are responsible for the listed percentage of the total amount of IPV4 records:\n");
        for (int i = 0; i < pairs.size(); i++) {
            temp = pairs.get(i).getCnt();
            percent = ((float) temp / ipv4) *100;
            System.out.printf("Source %s with Destination %s had %d total records for %.2f%%.\n",
                    pairs.get(i).srceToString(), pairs.get(i).destToString(), temp, percent);
        }

    }

    /**
     * Check the array list to see if the protocal is in it
     * @param tempProtocol - protocol to check
     * @param protocols - array list to check within
     * @return - -1 if not found otherwise the index location
     */
    private int checkProtocol(PacketProtocol tempProtocol, ArrayList<PacketProtocol> protocols) {
        for (int i = 0; i<protocols.size(); i++)
            if (protocols.get(i).getType() == tempProtocol.getType())
                return i;
        return -1;
    }

    /**
     * Under construction for item #3 but handled all Eth 2 stuff
     */
    public void ethernetIIPackets() {
        // Temporary to hold protocal object we are checking
        PacketProtocol tempProtocol;
        // Array list holding our protocol listing, total bytes used and how many of them there are
        ArrayList<PacketProtocol> protocols = new ArrayList<PacketProtocol>();
        // packet we are inspecting
        PcapPacket tempPacket;
        // initialize the variables. ieee and eth2 are counters, tipe is the type and percent is the calculation
        int ieee = 0;
        int eth2 = 0;
        int tipe;
        float percent;
        int temp;
        // used for part 3 totals
        int total2Bytes = 0;
        // step through all the records
        for (int i = 0; i < records; i++) {
            // grab a packet from the array list
            tempPacket = packets.get(i);
            // get the type
            tipe = tempPacket.getUShort(12);
            // anything 0x0800 (HEX) or higher are Ethernet II
            if (tipe < 0x0800) {
                ieee++;
            } else {
                // working on section 3 here
                tempProtocol = new PacketProtocol(tipe, tempPacket.size());
                total2Bytes += tempPacket.size();
                //System.out.printf("%d  bytes = %d  type = 0x%x\n", i, tempProtocol.getBites(), tempProtocol.getType()  ); // remove when done
                if ( protocols.size() ==0) {
                    protocols.add(tempProtocol);
                }
                else {
                    temp = checkProtocol(tempProtocol, protocols);
                    if ( temp >= 0) {
                        protocols.get(temp).addBites(tempProtocol.getBites());
                        protocols.get(temp).addCnt(1);
                    //    System.out.printf("Match found 0x%x now has %d entries with total of %d bytes\n",
                     //           protocols.get(temp).getType(), protocols.get(temp).getCnt(), protocols.get(temp).getBites());  // remove when done
                    } else {
                        protocols.add(tempProtocol);
                    }
                }

            }
            //System.out.printf("%d Type = %d or 0x%04x \n", i+1, tipe, tipe, tempPacket.getUShort(12));
        }
        // total number of eth2 records
        eth2 = records - ieee;
        // calculate percentage of total
        percent = ((float)ieee/(float)records)*100;
        System.out.printf("\nThere were %d IEEE 802.e packets for %.2f%% of total packets and %d Ethernet II packets for a total of %.2f%% of total packets.\n",
                ieee, percent, eth2, 100-percent);
        System.out.printf("There were a total %d bytes sent using Ethernet II packets and this was split into the following %d protocols:\n\n",
                total2Bytes, protocols.size());
        for (int i =0; i < protocols.size(); i++) {
            percent = ((float)protocols.get(i).getCnt()/eth2) *100;
            System.out.printf("Protocol 0x%04x had %d packets for a total of %.2f%% of total ethernet II packets containing\n",
                    protocols.get(i).getType(), protocols.get(i).getCnt(), percent);
            percent = ((float)protocols.get(i).getBites()/total2Bytes) *100;
            System.out.printf("     %d total bytes for %.2f%% of total bytes sent by all Ethernet II packets.\n",
                    protocols.get(i).getBites(),  percent);
        }
    }

}
