/**
 * Project 3 for CIS 457
 * Rodney Fulk
 * Laura Young
 */
package nettraffic;

/**
 * Class to store Protocol type, byte count and number of records
 */
public class PacketProtocol {

    private int type;
    private int cnt;
    private int bites;

    /**
     * Empty constructor - Initialize values
     */
    public PacketProtocol() {
        type = 0;
        cnt = 1;
        bites = 0;
    }

    /**
     * Normal constructor
     * @param type - protocol type
     * @param bites - bytes taken up by this packet
     */
    public PacketProtocol(int type, int bites) {
        cnt =1;
        initialize(type, bites);
    }

    /**
     * Actually does intilization of global bites and type
     * @param type - protocol type
     * @param bites - bytes taken up by packet
     */
    private void initialize(int type, int bites) {
        this.bites = bites;
        this.type = type;
    }

    /*
     rest of lines are used as getters, setters and add to the current value
     */
    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public void addType(int type) {
        this.type += type;
    }

    public int getBites() {
        return bites;
    }

    public void setBites(int bites) {
        this.bites = bites;
    }

    public void addBites(int bites) {
        this.bites += bites;
    }

    public int getCnt() {
        return cnt;
    }

    public void setCnt(int cnt) {
        this.cnt = cnt;
    }

    public void addCnt(int cnt) {
        this.cnt += cnt;
    }

}
