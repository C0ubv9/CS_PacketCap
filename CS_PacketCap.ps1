[CmdletBinding()]
param
(
	[Parameter(Mandatory=$True,Position=0)]
	[Int]$fileSize 
)

function CS_PacketCap {
<#	
.SYNOPSIS  
Powershell script to capture packet with CrowdStrike RTR

.DESCRIPTION
CS_PacketCap is a PowerShell script to capture packet with CrowdStrike Real Time Response.


[Important]
Packet captured will be saved as .etl file (Event Tracing for Windows <ETW> events) on local drive. To ensure not to fill up the drive space unintentionally, the maximum fileSize has been set to 50% of free space on the drive.  

.PARAMETER fileSize
	This is the maximum resultant file size(uncompressed, in megabytes) on the local drive. As mentioned above, it can be only set to less than or equal to 50% of free space on current drive.

.NOTEs:  
    
	All testing done on Windows 10 with PowerShell v5.1.
	The script has to been run with administrator right.
    The resultant .etl file will be compressed to save disk space and to reduce uploading time.
		
    Reference links:  
	
	https://devblogs.microsoft.com/scripting/packet-sniffing-with-powershell-getting-started/
	
	https://github.com/microsoft/etl2pcapng

#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory=$True,Position=0)]
		[Int]$fileSize 
	)

	begin{
			# Calculate free space on the drive and set max size to 50% of free space.
			$m= (Get-WmiObject -Class Win32_logicalDisk -Filter "DeviceID='c:'" -ComputerName 'localhost' | select -ExpandProperty FreeSpace)*0.5 / 1MB
			$maxsize = [math]::Round($m)
			write-host "The maximum size allowed is [$($maxsize)] megabytes, which is 50% of free space"
			
			# Here is the output directory.
			
			$outputDir = $env:TEMP +"\_CS_PacketCap"
	}	

	process {
		# outputDir and file size checking
		try {
		    # Check if specified file size is greater than max size allowed.
			if ($fileSize -gt $maxsize) {
				throw "File size is greater than maximum size allowed, which is [$($maxsize)] megabytes. Please specify smaller file size than this to avoid filling up the drive."
			} else {
				Write-host -Message "Packet capturing has been set to $filesize megabytes."
			}
			
			# Check if the outputDir exist on the drive.
			if (Test-Path -Path $outputDir) {
				throw "The output directory $outputDir already exists. Please check the files inside and delete it."
					
			} else {
				New-Item -Path $env:TEMP -Name "_CS_PacketCap" -ItemType "directory"
					}
								
			
		} catch {
			Write-Error -Message "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
            return
			} 

		# packet capturing session set up and tear down
		
		try {
			# Store the resultant .etl file temporarily to C:\Users\userprofile\AppData\Local\Temp\CollectionSession
			if (Test-Path -Path "$Env:TEMP\CollectionSession"){
				throw "It looks like this machine has run collection before. Please delete this folder - $Env:TEMP\CollectionSession."
			
			} else {
			New-Item -ItemType directory -Path "$Env:TEMP\CollectionSession"
			}
			# Follow basic steps to perform a network trace
			New-NetEventSession -CaptureMode SaveToFile -LocalFilePath "$Env:TEMP\CollectionSession\$env:computername.etl" -MaxFileSize $filesize -Name CS_collection
			Add-NetEventProvider -Name "Microsoft-Windows-TCPIP" -SessionName "CS_collection" -Level 0x0
			# Captuer IPv4 traffic only and set truncationlength to maximum ethernet size 1522 bytes
            Add-NetEventPacketCaptureProvider -SessionName "CS_collection" -EtherType 0x0800 -CaptureType Physical -TruncationLength 1522
            Start-NetEventSession -Name "CS_collection"
            Do{
			get-NetEventSession -Name "CS_collection" |Format-Table -Property Name,SessionStatus,LocalFilePath,MaxFileSize -AutoSize
			}
			while (
			(Get-Item "$Env:TEMP\CollectionSession\$env:computername.etl").length/1MB -lt $filesize
				)
			# Stop and clean up session after collection.
			Stop-NetEventSession "CS_collection"
			Remove-NetEventSession "CS_collection"
			
		} catch {
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
			return
				
		}
	

		# Data compression and clean up
		try{
			# Compress resultant data
            Compress-Archive -Path "$Env:TEMP\CollectionSession\$env:computername.etl" -CompressionLevel Fastest -DestinationPath "$outputDir\CS_collection.Zip"
            # Remove temp data
			Remove-Item -path "$Env:TEMP\CollectionSession\" -Recurse -Force
            write-host "The collection has finished successfully, please upload resultant data from $outputDir."

		} catch{
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
            return
				}
	}	
	end{}
}
CS_PacketCap -fileSize $filesize