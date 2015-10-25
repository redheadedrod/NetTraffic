/**
 * Project 3 for CIS 457
 * Rodney Fulk
 * Laura Young
 */
package nettraffic;

/**
 * This class is an object to make an arraylist out of to hold information about ipv4 parings
 */
public class IPV4AddressPairs {
    private byte[] srce;
    private byte[] dest;
    private int cnt;

    /**
     * empty constructor - doesn't initialize the srce or destination
     */
    public IPV4AddressPairs() {
        cnt =1;
    }

    /**
     * normally used constructor
     * @param srce - source address
     * @param dest - destination address
     */
    public IPV4AddressPairs(byte[] srce, byte[] dest) {
        cnt=1;
        setAddr(srce, dest);
    }

    /**
     * sets the globals upon initilization of values. If not done in constructor can do afterwards
     * @param srce
     * @param dest
     */
    public void setAddr(byte[] srce, byte[] dest) {
        this.dest = dest;
        this.srce = srce;
    }


    /*
      Following lines all are getters/setters and allow for conversion to strings.
     */
    public byte[] getSrce(){
        return srce;
    }

    public byte[] getDest() {
        return dest;
    }

    public int getCnt() {
        return cnt;
    }

    public void setSrce(byte[] srce) {
        this.srce = srce;
    }

    public void setDest(byte[] dest) {
        this.dest = dest;
    }

    public void setCnt(int cnt) {
       this.cnt = cnt;
    }

    public String srceToString() {
        return addrToString(srce);
    }

    public String destToString() {
        return addrToString(dest);
    }

    public String cntToString() {
        return Integer.toString(cnt);
    }

    /**
     * Count incrementer
     */
    public void incCnt() {
        cnt++;
    }

    /**
     * Main toString for whole object
     * @return - returns string to disaplay object results
     */
    @Override
    public String toString() {
        return srceToString() + ", "+ destToString() + ", " + cntToString();
    }

    /**
     * This routine converts an address from byte array to a normal ipv4 style IP address
     * @param input - the byte array to convert
     * @return - return a standard ipv4 formated string
     */
    private String addrToString(byte[] input){
        String temp = "";
        for (int i = 0; i < 4; i++) {
            // necissary to prevent value from becoming negative if first bit is set
            temp += Integer.toString(input[i] & 0x000000ff);
            if (i < 3) temp += ".";
        }
        return temp;
    }
}
