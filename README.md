# CS_PacketCap
Custom powershell script to enable Windows native packet capture with CrowdStrike RTR. 

## About

CrowdStrike RTR(Real Time Response) allows analyst to run custom powershell script on the target system. It may come in handy to have a script that can enable Windows native packet capture in the event deep dive packet analysis is warranted. 

## Usage
   
1. Upload CS_PacketCap.ps1 via CrowdStrike RTR script UI
2. Pick script from CrowdStrike RTR script UI while connecting to the target host
3. Run command below:

   runscript -CloudFile= “ CS_PacketCap” CommandLine= “x”
       (x – the resultant file size you want to capture)

4. The maximal allowed file size has been hard-coded to 50% of local drive free space. The script will error out if user specifies bigger size than that.
5. The default output directory has been set to C:\windows\temp\_CS_PacketCap.
6. The resultant data(zip file) can be uploaded to CrowdStrike Cloud from output location using “get” command.
7. Remember to delete output data after successful uploading.
8. Download etl2pcapng from link below to convert .etl to pcap and load it to your favorite packet analysis tool. Then happy hunting!
   
   https://github.com/microsoft/etl2pcapng

## Acknowledgments

https://devblogs.microsoft.com/scripting/packet-sniffing-with-powershell-getting-started

