package nettraffic;

public class NetTraffic {
    public static ProcessPacket pp;
    public static void main (String args[]) {
        String file = "C:\\Users\\Rodney\\SkyDrive\\School\\CIS 457 Datacom\\NetTraffic\\src\\nettraffic\\sample.pcap"; // May need to be changed to actual filename or pass on cl
        if (args.length>0)
            file = args[0];
        pp = new ProcessPacket(file);
        pp.ProcessFile();
    }

}
