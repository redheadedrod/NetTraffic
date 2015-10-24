package nettraffic;

public class NetTraffic {
    public static ProcessPacket pp;
    public static void main (String args[]) {
        if (args.length>0)
            pp = new ProcessPacket(args[0]);
        else
            pp = new ProcessPacket();
        //pp.ethernetIIPackets();
        System.out.println("Number of records read in = " + Integer.toString(pp.length()));
    }

}
