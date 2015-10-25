/**
 * Project 3 for CIS 457
 * Rodney Fulk
 * Laura Young
 */
package nettraffic;

/**
 * Our main class that runs the rest of the project
 */
public class NetTraffic {
    // Object that holds our loaded packets
    public static ProcessPacket pp;
    public static void main (String args[]) {
        // file length is entered on command line or will default - load file into our object
        if (args.length>0)
            pp = new ProcessPacket(args[0]);
        else
            pp = new ProcessPacket();
        // Shows we did #1 although not necessary
        System.out.println("Number of records read in = " + Integer.toString(pp.length()));
        // Identifies Ethernet II packets, prints out percentage of packets that are Ethernet II and
        // prints out the protocols used, the number of packets per protocol and the number of bytes used total by each protocol
        pp.ethernetIIPackets();
        // finds pairs of IPV4 source/destinations and prints them with their percentages
        pp.ipv4PacketAddresses();
    }

}
