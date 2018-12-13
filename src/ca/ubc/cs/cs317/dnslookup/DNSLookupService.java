package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Consumer;


public class DNSLookupService {
    
    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;
    
    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;
    private static RecordType type;
    private static DNSCache cache = DNSCache.getInstance();
    
    private static Random random = new Random();
    
    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {
        
        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }
        
        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }
        
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
        
        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;
            
            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];
            
            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;
            
            String[] commandArgs = commandLine.split(" ");
            
            if (commandArgs[0].equalsIgnoreCase("quit") ||
                commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                       commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.

                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }
            
        } while (true);
        
        socket.close();
        System.out.println("Goodbye!");
    }
    
    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }
    
    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        //Cname checker
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        //if result is already chaced return it
        if(!cache.getCachedResults(node).isEmpty()){
            return cache.getCachedResults(node);
        }

        //if nothing is in cache populate it
        if(cache.getCachedResults(node).isEmpty()){
            retrieveResultsFromServer(node, rootServer);
        }

        //call for cname when given that as a result
        DNSNode cnameNode = new DNSNode(node.getHostName(), RecordType.CNAME);
        Set<ResourceRecord> resourceRecords = cache.getCachedResults(cnameNode);

        if (!resourceRecords.isEmpty()) {
            final ResourceRecord r = (ResourceRecord)resourceRecords.toArray()[0];
            final DNSNode dnsNode = new DNSNode(r.getTextResult(), type);
            return getResults(dnsNode, indirectionLevel + 1);
        }

        //defaults to answer if code worked
        return cache.getCachedResults(node);

    }
    
    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {


        
        try{
            //creates header for datagram
            byte[] header = createHeaderRequest();
            int headerlength = header.length;
            //creates question header for datagram
            byte[] question = createQuestionRequest(node);
            int questionlength = question.length;
            //adds both together
            ByteBuffer requestData = ByteBuffer.allocate(headerlength + questionlength);
            requestData.put(header);
            requestData.put(question);
            //sends datagram packet
            byte[] arr = requestData.array();
            DatagramPacket requestPacket = new DatagramPacket(arr,headerlength+questionlength,server,DEFAULT_DNS_PORT);
            socket.send(requestPacket);
            //recieves datagram packet
            byte[] buffer3 = new byte[1024];
            DatagramPacket recievePacket = new DatagramPacket(buffer3, buffer3.length);
            socket.receive(recievePacket);
            //starts decoding
            decodeMessage(recievePacket.getData(),requestData.array().length,node.getType(), server, node);
        }catch(Exception e){
            System.err.println("error occurred");
        }
        // TODO To be completed by the student
    }
    
    
    private static void decodeMessage(byte[] response, int requestlength, RecordType type, InetAddress server,DNSNode node){

        ResourceRecord temp;
        boolean noRecords = false;
        recordData tempHolder = null;
        int offset = requestlength;
        validateQuestionType(response, type);
        
        //ID
        byte[] ID = new byte[2];
        ID[0] = response[0];
        ID[1] = response[1];
        
        //QR
        boolean QR = getBit(response[2], 7) == 1;
        
        //AA
        boolean AA = getBit(response[2], 2) == 1;
        
        //TC
        boolean TC = getBit(response[2], 1) == 1;
        
        //RD
        boolean RD = getBit(response[2], 0) == 1;
        
        //RA
        boolean A = getBit(response[3], 7) == 1;
        
        //RCODE
        int RCode = response[3] & 0x0F;
        
        //QDCount
        byte[] QDCount1 = { response[4], response[5] };
        ByteBuffer wrapped = ByteBuffer.wrap(QDCount1);
        int QDCount = wrapped.getShort();
        
        //ANCount
        byte[] ANCount1 = { response[6], response[7] };
        wrapped = ByteBuffer.wrap(ANCount1);
        int ANCount = wrapped.getShort();
        
        //NSCount
        byte[] NSCount1 = { response[8], response[9] };
        wrapped = ByteBuffer.wrap(NSCount1);
        int NSCount = wrapped.getShort();
        
        //ARCount
        byte[] ARCount1 = { response[10], response[11] };
        wrapped = ByteBuffer.wrap(ARCount1);
        int ARCount = wrapped.getShort();
        
        //Answer and printing format
        
        System.out.println();
        System.out.println();
        System.out.println("Query ID     "+ ID[0]+ID[1] +" "+node.getHostName()+"  "+node.getType()+" "+"--> "+server.getHostAddress());
        System.out.println();
        if(ANCount==0)
            System.out.println("Response ID: "+ID[0]+ID[1]+" " + "Authoritative = "+" false");
        else
            System.out.println("Response ID: "+ "" + "Authoritative = "+" true");
        System.out.println();
        System.out.println("  Answers "+"("+ANCount+")");
        ResourceRecord[] answerRecords = new ResourceRecord[ANCount];
        for(int i = 0; i < ANCount; i++){
            tempHolder = getData(response, offset);
            temp = tempHolder.getRecord();
            cache.addResult(temp);
            answerRecords[i] = tempHolder.getRecord();
            verbosePrintResourceRecord(tempHolder.getRecord(),1);
            offset += tempHolder.getOffset();
        }
        
        //nameserver and printing format
        System.out.println();
        System.out.println("  Nameservers "+"("+NSCount+")");
        ResourceRecord[] nameserverRecords = new ResourceRecord[NSCount];
        for(int i = 0; i < NSCount; i++){
            tempHolder = getData(response, offset);
            temp = tempHolder.getRecord();
            cache.addResult(temp);
            nameserverRecords[i] = tempHolder.getRecord();
            verbosePrintResourceRecord(tempHolder.getRecord(),1);
            
            offset += tempHolder.getOffset();
        }
        
        //Additional records and printing format
        
        System.out.println();
        System.out.println("  Additional Information "+"("+ARCount+")");
        ResourceRecord[] ADrecords = new ResourceRecord[ARCount];
        for(int i = 0; i < ARCount; i++){
            tempHolder = getData(response, offset);
            temp = tempHolder.getRecord();
            cache.addResult(temp);
            ADrecords[i] = tempHolder.getRecord();
            verbosePrintResourceRecord(tempHolder.getRecord(),1);
            offset += tempHolder.getOffset();
        }
        
        try{
            checkRCodeForErrors(RCode);
        }catch(Exception e){
            System.err.println("RCODE VIOLATED");
        }
        
        validateQueryType(QR);

        try {
            if (ANCount == 0 && ADrecords.length > 0) {
                String hostName = ADrecords[0].getHostName();
                retrieveResultsFromServer(node, InetAddress.getByName(hostName));
            }else if(NSCount != 0){
                //resolves nameserver edge case but breaks cname resolver
              Set<ResourceRecord> values = getResults(new DNSNode(nameserverRecords[0].getTextResult(), RecordType.A), 0);
            // ResourceRecord v = (ResourceRecord)values.toArray()[0];
            // retrieveResultsFromServer(node, v.getInetResult());
            }
        } catch (UnknownHostException e) {
        }

    }
    
    //Returns an error if Rcode is anything but 0
    private static void checkRCodeForErrors(int RCode) {
        switch(RCode) {
            case 0:
                //No error
                break;
            case 1:
                throw new RuntimeException("Format error - The name server was\n" +
                        "                                unable to interpret the query.");
            case 2:
                throw new RuntimeException("Server failure - The name server was\n" +
                        "                                unable to process this query due to a\n" +
                        "                                problem with the name server.");
            case 3:
                throw new RuntimeException("Name Error - Meaningful only for\n" +
                        "                                responses from an authoritative name\n" +
                        "                                server, this code signifies that the\n" +
                        "                                domain name referenced in the query does\n" +
                        "                                not exist.");
            case 4:
                throw new RuntimeException("Not Implemented - The name server does\n" +
                        "                                not support the requested kind of query.");
            case 5:
                throw new RuntimeException("Refused - The name server refuses to\n" +
                        "                                perform the specified operation for\n" +
                        "                                policy reasons.  For example, a name\n" +
                        "                                server may not wish to provide the\n" +
                        "                                information to the particular requester,\n" +
                        "                                or a name server may not wish to perform\n" +
                        "                                a particular operation (e.g., zone transfer) for particular data.");
        }
    }
    
    //if QR isn't 1 send an error because it isn't a response
    private static void validateQueryType(boolean QR){
        if(!QR){
            throw new RuntimeException("message is not a response");
        }
    }
    
    
    
    // goes through each record for data needed.
    private static recordData getData(byte[] response, int offset){
        
        //make a resouce at end
        InetAddress ip = null;
        ResourceRecord recordValue = null;
        String name = "";
        String domain = "";
        int amountOfBytes = offset;
        
        rDataEntry domainResult = getDomainFromIndex(amountOfBytes, response);
        amountOfBytes += domainResult.getBytes();
        
        //name
        name = domainResult.getDomain();
        
        //recordtype
        byte[] ans_type = new byte[2];
        ans_type[0] = response[amountOfBytes];
        ans_type[1] = response[amountOfBytes + 1];
        RecordType typevalue = getTypeFromArray(ans_type);
        
        //offset
        amountOfBytes += 2;
        
        //record class
        byte[] ans_class = new byte[2];
        ans_class[0] = response[amountOfBytes];
        ans_class[1] = response[amountOfBytes+1];
        
        //error is offset is wrong
        if (ans_class[0] != 0 && ans_class[1] != 1) {
            throw new RuntimeException(("ERROR\tThe class field in the response answer is not 1"));
        }
        
        //offset
        amountOfBytes += 2;
        
        //TTL
        byte[] TTL = { response[amountOfBytes], response[amountOfBytes + 1], response[amountOfBytes + 2], response[amountOfBytes + 3]};
        ByteBuffer wrapped = ByteBuffer.wrap(TTL);
        int ttl = wrapped.getInt();
        
        //offset
        amountOfBytes += 4;
        
        //RDlength
        byte[] RDlength = { response[amountOfBytes], response[amountOfBytes + 1]};
        ByteBuffer wrapped2 = ByteBuffer.wrap(RDlength);
        int rDLength = wrapped2.getShort();
        
        //offset
        amountOfBytes += 2;
        
        //ip/domain value
        switch(typevalue){
            case A:
                ip = parseATypeRDATA(rDLength, amountOfBytes, response);
                recordValue = new ResourceRecord(name, typevalue, ttl, ip);
                break;
            case NS:
                domain = parseNSTypeRDATA(rDLength, amountOfBytes, response);
                recordValue = new ResourceRecord(name, typevalue, ttl, domain);
                break;
            case MX:
                domain = "---";
                recordValue = new ResourceRecord(name, typevalue, ttl, domain);
                break;
            case CNAME:
                domain = parseCNAMETypeRDATA(rDLength, amountOfBytes, response);
                recordValue = new ResourceRecord(name, typevalue, ttl, domain);
                break;
            case SOA:
                domain = "---";
                recordValue = new ResourceRecord(name, typevalue, ttl, domain);
            case AAAA:
                ip = parseAAAATypeRDATA(rDLength, amountOfBytes, response);
                recordValue = new ResourceRecord(name, typevalue, ttl, ip);
            case OTHER:
                break;
        }
        
        //offset for new record area
        int newLength = amountOfBytes + rDLength - offset;
        //struct made to store values
        recordData answer = new recordData(newLength, recordValue);
        
        return answer;
    }
    
    
    
    // gets address for type A
    private static InetAddress parseATypeRDATA(int rDLength, int countByte, byte[] response) {
        InetAddress inetaddress = null;
        byte[] byteAddress= { response[countByte], response[countByte + 1], response[countByte + 2], response[countByte + 3] };
        try {
            inetaddress = InetAddress.getByAddress(byteAddress);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return inetaddress;
        
    }
    
    // gets nameserver for type
    private static String parseNSTypeRDATA(int rDLength, int countByte, byte[] response) {
        rDataEntry result = getDomainFromIndex(countByte, response);
        String nameServer = result.getDomain();
        return nameServer;
    }
    
    //gets cname for type
    private static String parseCNAMETypeRDATA(int rDLength, int countByte, byte[] response) {
        rDataEntry result = getDomainFromIndex(countByte, response);
        String cname = result.getDomain();
        return cname;
    }
    
    //gets IPv6 address
    private static InetAddress parseAAAATypeRDATA(int rDLength, int countByte, byte[] response) {
        InetAddress inetaddress = null;
        byte[] byteAddress= { response[countByte], response[countByte + 1], response[countByte + 2], response[countByte + 3],
            response[countByte + 4], response[countByte + 5], response[countByte + 6], response[countByte + 7],
            response[countByte + 8], response[countByte + 9], response[countByte + 10], response[countByte + 11],
            response[countByte + 12], response[countByte + 13], response[countByte + 14], response[countByte + 15]};
        try {
            inetaddress = InetAddress.getByAddress(byteAddress);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return inetaddress;
    }
    

    //checks to see if rtype is still valid
    private static void validateQuestionType(byte[] response, RecordType type){
        int index = 12;
        while(response[index] != 0){
            index++;
        }
        byte[] rType = {response[index+1], response[index+2]};
        if(getTypeFromArray(rType) != type){
            throw new RuntimeException("Response query doesn't match request query");
        }
    }

    //returns a byte as bits and allows me to get the value at x position
    private static int getBit(byte b, int position) {
        return (b >> position) & 1;
    }


    //returns the corrsponding recordtype based off the numerical value stored in rType
    private static RecordType getTypeFromArray(byte[] rType){
        //0 (some value 1-15)
        if(rType[0] == 0){
            if (rType[1] == 1) {
                return RecordType.A;
            } else if (rType[1] == 2) {
                return RecordType.NS;
            } else if (rType[1] == 15) {
                return  RecordType.MX;
            } else if (rType[1] == 5) {
                return RecordType.CNAME;
            } else if (rType[1] == 28){
                return RecordType.AAAA;
            } else {
                return RecordType.OTHER;
            }
            // 28 or other
        } else if(rType[0] == 1) {
            return RecordType.AAAA;
        }else {
            return RecordType.OTHER;
        }
    }

    //returns a website name
    private static rDataEntry getDomainFromIndex(int index, byte[] response){
        rDataEntry result = new rDataEntry();
        int wordSize = response[index];
        String domain = "";
        boolean start = true;
        int count = 0;
        while(wordSize != 0){
            if (!start){
                domain += ".";
            }
            if ((wordSize & 0xC0) == (int) 0xC0) {
                byte[] offset = { (byte) (response[index] & 0x3F), response[index + 1] };
                ByteBuffer wrapped = ByteBuffer.wrap(offset);
                domain += getDomainFromIndex(wrapped.getShort(), response).getDomain();
                index += 2;
                count +=2;
                wordSize = 0;
            }else{
                domain += getWordFromIndex(index, response);
                index += wordSize + 1;
                count += wordSize + 1;
                wordSize = response[index];
            }
            start = false;
            
        }
        result.setDomain(domain);
        result.setBytes(count);
        
        return result;
    }
    
    //takes in a index and byte and returns the word (website)
    private static String getWordFromIndex(int index, byte[] response){
        String word = "";
        int wordSize = response[index];
        for(int i =0; i < wordSize; i++){
            word += (char) response[index + i + 1];
        }
        return word;
    }
    
    //creates the header request
    private static byte[] createHeaderRequest(){
        ByteBuffer header = ByteBuffer.allocate(12);
        byte[] randomID = new byte[2];
        new Random().nextBytes(randomID);
        header.put(randomID);
        header.put((hexStringToByteArray("00")));
        header.put((hexStringToByteArray("00")));
        header.put((hexStringToByteArray("00")));
        header.put((hexStringToByteArray("01")));
        return header.array();
    }
    

    //creates the request for header
    private static byte[] createQuestionRequest(DNSNode node){

        //finds size for buffer
        int bufferSize = getHostNameLength(node);
        ByteBuffer question = ByteBuffer.allocate(bufferSize + 5);
        String[] items = node.getHostName().split("\\.");

        //converts webname into hex an puts it in question
        for(int i=0; i < items.length; i ++){
            question.put((byte) items[i].length());
            for (int j = 0; j < items[i].length(); j++){
                question.put(hexStringToByteArray(Integer.toHexString((int) items[i].charAt(j))));
                
            }
        }

        //temerimate hostname
        question.put((hexStringToByteArray("00")));
        //rtype
        question.put((hexStringToByteArray("00")));
        question.put(typeByteArray(node.getType().getCode()));
        //rclass
        question.put((hexStringToByteArray("00")));
        question.put((hexStringToByteArray("01")));
        //rest of values are 0s
        return question.array();
        
    }

    // turns a type into a byte array
    private static byte[] typeByteArray(int recordtypevalue){
        if(recordtypevalue < 16){
            return hexStringToByteArray( "0" + Integer.toHexString(recordtypevalue));
        }
        return hexStringToByteArray(Integer.toHexString(recordtypevalue));
        
    }
    
    //returns the length of a host name for byte array
    private static int getHostNameLength(DNSNode node){
        int buffercount = 0;
        String[] items = node.getHostName().split("\\.");
        for(int i = 0; i < items.length; i++){
            buffercount += (1 + items[i].length());
        }
        
        return buffercount;
    }

    //converts hexstrings to byte arrays
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                  + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    
    
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                              record.getTTL(),
                              record.getType() == RecordType.OTHER ? rtype : record.getType(),
                              record.getTextResult());
    }
    
    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                              node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                              node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}

//struct created to store the offset and record
class recordData {
    private int offset;
    private ResourceRecord record;
    public recordData(int offset, ResourceRecord record){
        this.offset = offset;
        this.record = record;
    }
    public int getOffset(){ return offset; }
    public ResourceRecord getRecord(){ return  record; }
    
}

//struct to obtain the website name from a encoding value
class rDataEntry {
    private int bytes;
    private String domain;
    public int getBytes() {
        return bytes;
    }
    public void setBytes(int bytes) {
        this.bytes = bytes;
    }
    public String getDomain() {
        return domain;
    }
    public void setDomain(String domain) {
        this.domain = domain;
    }
}

