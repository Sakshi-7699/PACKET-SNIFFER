import socket, sys, time, platform, struct
from PyQt4 import QtGui, QtCore

class SniffThread(QtCore.QThread):
	def eth(self, packet, extractedAttIndex, printKey):
		ethHeaderLength = 14
		begin = 0
		end = begin + ethHeaderLength
		ethHeader = packet[begin:end]
		# ! signifies we are unpacking a network endian.
		# 6s signifies we are unpacking a string of size 6 bytes.
		# H signifies we are unpacking an integer of size 2 bytes.
		ethHeaderUnpacked = struct.unpack('!6s6sH', ethHeader)
		ethDestAddress = ethHeaderUnpacked[0]
		ethSourceAddress = ethHeaderUnpacked[1]
		ethType = socket.ntohs(ethHeaderUnpacked[2])
		ethDestAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ethDestAddress[0]), ord(ethDestAddress[1]), ord(ethDestAddress[2]), ord(ethDestAddress[3]), ord(ethDestAddress[4]), ord(ethDestAddress[5]))
		
		ethSourceAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ethSourceAddress[0]), ord(ethSourceAddress[1]), ord(ethSourceAddress[2]), ord(ethSourceAddress[3]), ord(ethSourceAddress[4]), ord(ethSourceAddress[5]))
		
		if printKey == 0:
			self.unpackedInfo.append('\n********************\n** Ethernet (MAC) **\n********************')
			
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Destination Address: ' + str(ethDestAddress))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Source Address: ' + str(ethSourceAddress))
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
					self.unpackedInfo.append('EtherType: ' + str(ethType))
		else:
			if (extractedAttIndex == 1):
				return str(ethDestAddress)
			if (extractedAttIndex == 2):
				return str(ethSourceAddress)
			if (extractedAttIndex == 3):
				return str(ethType)
		
	def arp(self, packet, extractedAttIndex, printKey):
		ethHeaderLength = 14
		arpHeaderLength = 28
		begin = ethHeaderLength
		end = begin + arpHeaderLength
		arpHeader = packet[begin:end]
		# ! signifies we are unpacking a network endian.
		# H signifies we are unpacking an integer of size 2 bytes.
		# B signifies we are unpacking an integer of size 1 byte.
		# 6s signifies we are unpacking a string of size 6 bytes.
		# 4s signifies we are unpacking a string of size 4 bytes.
		arpHeaderUnpacked = struct.unpack('!HHBBH6s4s6s4s', arpHeader)
		arpHardwareType = socket.ntohs(arpHeaderUnpacked[0])
		arpProtocolType = socket.ntohs(arpHeaderUnpacked[1])
		arpHardAddressLength = arpHeaderUnpacked[2]
		arpProtAddressLength = arpHeaderUnpacked[3]
		arpOperation = arpHeaderUnpacked[4]
		arpSenderHardAddress = arpHeaderUnpacked[5]
		arpSenderProtAddress = socket.inet_ntoa(arpHeaderUnpacked[6])
		arpTargetHardAddress = arpHeaderUnpacked[7]
		arpTargetProtAddress = socket.inet_ntoa(arpHeaderUnpacked[8])
		arpSenderHardAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(arpSenderHardAddress[0]), ord(arpSenderHardAddress[1]), ord(arpSenderHardAddress[2]), ord(arpSenderHardAddress[3]), ord(arpSenderHardAddress[4]), ord(arpSenderHardAddress[5]))
		

		arpTargetHardAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(arpTargetHardAddress[0]), ord(arpTargetHardAddress[1]), ord(arpTargetHardAddress[2]), ord(arpTargetHardAddress[3]), ord(arpTargetHardAddress[4]), ord(arpTargetHardAddress[5]))

		if printKey == 0:
			self.unpackedInfo.append('\n*******************\n******* ARP *******\n*******************')
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Hardware Type: ' + str(arpHardwareType))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Protocol Type: ' + str(arpProtocolType))
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Hardware Address Length: ' + str(arpHardAddressLength))
			if (extractedAttIndex == 4) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Protocol Address Length: ' + str(arpProtAddressLength))
			if (extractedAttIndex == 5) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Operation: ' + str(arpOperation))
			if (extractedAttIndex == 6) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Sender Hardware Address: ' + str(arpSenderHardAddress))
			if (extractedAttIndex == 7) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Sender Protocol Address: ' + str(arpSenderProtAddress))
			if (extractedAttIndex == 8) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Target Hardware Address: ' + str(arpTargetHardAddress))
			if (extractedAttIndex == 9) or (extractedAttIndex == 0):	
				self.unpackedInfo.append('Target Protocol Address: ' + str(arpTargetProtAddress))

			self.unpackedInfo.append('\n----------------------------------------')

		else:
			if (extractedAttIndex == 1):
				return str(arpHardwareType)
			if (extractedAttIndex == 2):	
				return str(arpProtocolType)
			if (extractedAttIndex == 3):	
				return str(arpHardAddressLength)
			if (extractedAttIndex == 4):	
				return str(arpProtAddressLength)
			if (extractedAttIndex == 5):	
				return str(arpOperation)
			if (extractedAttIndex == 6):	
				return str(arpSenderHardAddress)
			if (extractedAttIndex == 7):	
				return str(arpSenderProtAddress)
			if (extractedAttIndex == 8):	
				return str(arpTargetHardAddress)
			if (extractedAttIndex == 9):	
				return str(arpTargetProtAddress)

	def ip(self, packet, extractedAttIndex, printKey):
		ethHeaderLength = 14
		ipHeaderLength = 22
		begin = ethHeaderLength
		end = begin + ipHeaderLength
		ipHeader = packet[begin:end]
		# ! signifies we are unpacking a network endian.
		# B signifies we are unpacking an integer of size 1 byte.
		# H signifies we are unpacking an integer of size 2 bytes.
		# 4s signifies we are unpacking a string of size 4 bytes.
		ipHeaderUnpacked = struct.unpack('!BBHHHBBH4s4sH' , ipHeader)
		ipVersionAndHeaderLength = ipHeaderUnpacked[0]
		ipVersion = ipVersionAndHeaderLength >> 4
		ipHeaderLength = ipVersionAndHeaderLength & 0xF
		ipDSCPAndECN = ipHeaderUnpacked[1]
		ipDSCP = ipDSCPAndECN >> 2
		ipECN = ipDSCPAndECN & 0x3
		ipTotalLength = ipHeaderUnpacked[2]
		ipIdentification = ipHeaderUnpacked[3]
		ipFlagsAndFragmentOffset = ipHeaderUnpacked[4]
		ipFlags = ipFlagsAndFragmentOffset >> 13
		ipFragmentOffset = ipFlagsAndFragmentOffset & 0x1FFF
		ipTimeToLive = ipHeaderUnpacked[5]
		ipProtocol = ipHeaderUnpacked[6]
		ipHeaderChecksum = ipHeaderUnpacked[7]
		ipSourceAddress = socket.inet_ntoa(ipHeaderUnpacked[8]);
		ipDestAddress = socket.inet_ntoa(ipHeaderUnpacked[9]);
		ipoptions = ipHeaderUnpacked[10]
		ipoptions = oct(ipoptions)		
		if printKey == 0:
			self.unpackedInfo.append('\n********************\n******** IP ********\n********************')
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Version: ' + str(ipVersion))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Header Length: ' + str(ipHeaderLength) + ' 32-bit words')
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Differentiated Services Code Point: ' + format(ipDSCP, '#04X') + ' , ' + str(ipDSCP))
			if (extractedAttIndex == 4) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Explicit Congestion Notification: ' + format(ipECN, '#04X') + ' , ' + str(ipECN))
			if (extractedAttIndex == 5) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Total Length: ' + str(ipTotalLength) + ' bytes')
			if (extractedAttIndex == 6) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Identification: ' + format(ipIdentification, '#04X') + ' , ' + str(ipIdentification))
			if (extractedAttIndex == 7) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Flags: ' + format(ipFlags, '#04X') + ' , ' + str(ipFlags))
			if (extractedAttIndex == 8) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Fragment Offset: ' + str(ipFragmentOffset) + ' eight-byte blocks')
			if (extractedAttIndex == 9) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Time to Live: ' + str(ipTimeToLive) + ' hops')
			if (extractedAttIndex == 10) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Protocol: ' + str(ipProtocol))
			if (extractedAttIndex == 11) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Header Checksum: ' + format(ipHeaderChecksum, '#04X'))
			if (extractedAttIndex == 12) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Source Address: ' + str(ipSourceAddress))
			if (extractedAttIndex == 13) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Destination Address: ' + str(ipDestAddress))
			if (extractedAttIndex == 14) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Options: ' + str(ipoptions))

		else:
			if (extractedAttIndex == 1):
				return str(ipVersion)
			if (extractedAttIndex == 2):
				return str(ipHeaderLength)
			if (extractedAttIndex == 3):
				return format(ipDSCP, '#04X')
			if (extractedAttIndex == 4):
				return format(ipECN, '#04X')
			if (extractedAttIndex == 5):
				return str(ipTotalLength)
			if (extractedAttIndex == 6):
				return format(ipIdentification, '#04X')
			if (extractedAttIndex == 7):
				return format(ipFlags, '#04X')
			if (extractedAttIndex == 8):
				return str(ipFragmentOffset)
			if (extractedAttIndex == 9):
				return str(ipTimeToLive)
			if (extractedAttIndex == 10):
				return str(ipProtocol)
			if (extractedAttIndex == 11):
				return format(ipHeaderChecksum, '#04X')
			if (extractedAttIndex == 12):
				return str(ipSourceAddress)
			if (extractedAttIndex == 13):
				return str(ipDestAddress)
			if (extractedAttIndex == 14):
				return str(ipoptions)	
	def icmp(self, packet, extractedAttIndex, printKey):
		ethHeaderLength = 14
		ipHeaderLength = 20
		icmpHeaderLength = 8
		begin = ethHeaderLength + ipHeaderLength
		end = begin + icmpHeaderLength
		icmpHeader = packet[begin:end]
		# ! signifies we are unpacking a network endian.
		# B signifies we are unpacking an integer of size 1 byte.
		# H signifies we are unpacking an integer of size 2 bytes.
		# L signifies we are unpacking a long of size 4 bytes.
		icmpHeaderUnpacked = struct.unpack('!BBHL', icmpHeader)
		icmpType = icmpHeaderUnpacked[0]
		icmpCode = icmpHeaderUnpacked[1]
		icmpChecksum = icmpHeaderUnpacked[2]
		if (icmpType == 0) or (icmpType == 8):
			icmpIdentifier = icmpHeaderUnpacked[3] >> 16
			icmpSeqNumber = icmpHeaderUnpacked[3] & 0xFFFF
		if printKey == 0:
			if (icmpType == 0) or (icmpType == 8):
				self.unpackedInfo.append('\n********************\n******* ICMP *******\n********************')
				if (extractedAttIndex == 1) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Type: ' + str(icmpType))
				if (extractedAttIndex == 2) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Code: ' + str(icmpCode))
				if (extractedAttIndex == 3) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Checksum: ' + format(icmpChecksum, '#04X'))
				if (extractedAttIndex == 4) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Identifier: ' + str(icmpIdentifier))
				if (extractedAttIndex == 5) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Sequence Number: ' + str(icmpSeqNumber))
			else:
				self.unpackedInfo.append('\n********************\n******* ICMP *******\n********************')	
				if (extractedAttIndex == 1) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Type: ' + str(icmpType))
				if (extractedAttIndex == 2) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Code: ' + str(icmpCode))
				if (extractedAttIndex == 3) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Checksum: ' + format(icmpChecksum, '#04X'))
				if (extractedAttIndex == 4) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Attribute not available.')
				if (extractedAttIndex == 5) or (extractedAttIndex == 0):
					self.unpackedInfo.append('Attribute not available.')					
			self.unpackedInfo.append('\n----------------------------------------')
		else:
			if (icmpType == 0) or (icmpType == 8):
				if (extractedAttIndex == 1):
					return str(icmpType)
				if (extractedAttIndex == 2):
					return str(icmpCode)
				if (extractedAttIndex == 3):
					return format(icmpChecksum, '#04X')
				if (extractedAttIndex == 4):
					return str(icmpIdentifier)
				if (extractedAttIndex == 5):
					return str(icmpSeqNumber)
			else:			
				if (extractedAttIndex == 1):
					return str(icmpType)
				if (extractedAttIndex == 2):
					return str(icmpCode)
				if (extractedAttIndex == 3):
					return format(icmpChecksum, '#04X')
				if (extractedAttIndex == 4):
					return 'Attribute not available.'
				if (extractedAttIndex == 5):
					return 'Attribute not available.'
		
	def tcp(self, packet, extractedAttIndex, printKey):
		ethHeaderLength = 14
		ipHeaderLength = 22
		tcpHeaderLength = 22
		begin = ethHeaderLength + ipHeaderLength
		end = begin + tcpHeaderLength
		tcpHeader = packet[begin:end]
		tcpHeaderUnpacked = struct.unpack('!HHLLBBHHHH', tcpHeader)
		tcpSourcePort = tcpHeaderUnpacked[0]
		tcpDestPort = tcpHeaderUnpacked[1]
		tcpSeqNumber = tcpHeaderUnpacked[2]
		tcpAckNumber = tcpHeaderUnpacked[3]
		tcpDataOffsetAndReserved = tcpHeaderUnpacked[4]
		tcpDataOffset = tcpDataOffsetAndReserved >> 4
		tcpReserved = (tcpDataOffsetAndReserved >> 1) & 0x7
		tcpNSFlag = tcpDataOffsetAndReserved & 0x1
		
		tcpRestOfFLags = tcpHeaderUnpacked[5]
		tcpCWRFlag = tcpRestOfFLags >> 7
		tcpECEFlag = (tcpRestOfFLags >> 6) & 0x1
		tcpURGFlag = (tcpRestOfFLags >> 5) & 0x1
		tcpACKFlag = (tcpRestOfFLags >> 4) & 0x1
		tcpPSHFlag = (tcpRestOfFLags >> 3) & 0x1
		tcpRSTFlag = (tcpRestOfFLags >> 2) & 0x1
		tcpSYNFlag = (tcpRestOfFLags >> 1) & 0x1
		tcpFINFlag = tcpRestOfFLags & 0x1
		tcpWindowSize = tcpHeaderUnpacked[6]
		tcpChecksum = tcpHeaderUnpacked[7]
		tcpUrgentPointer = tcpHeaderUnpacked[8]
		tcpoptions = tcpHeaderUnpacked[9]
		tcpoptions = oct(tcpoptions)
		if printKey == 0:
			self.unpackedInfo.append('\n*******************\n******* TCP *******\n*******************')
		
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Source Port: ' + str(tcpSourcePort))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Destination Port: ' + str(tcpDestPort))
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Sequence Number: ' + str(tcpSeqNumber))
			if (extractedAttIndex == 4) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Acknowledgment Number: ' + str(tcpAckNumber))
			if (extractedAttIndex == 5) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Data Offset: ' + str(tcpDataOffset) + ' 32-bit words')
			if (extractedAttIndex == 6) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Reserved: ' + format(tcpReserved, '03b') + '. .... ....')
			if (extractedAttIndex == 7) or (extractedAttIndex == 0):
				self.unpackedInfo.append('NS Flag:  ' + '...' + format(tcpNSFlag, '01b') + ' .... ....')
			if (extractedAttIndex == 8) or (extractedAttIndex == 0):
				self.unpackedInfo.append('CWR Flag: ' + '.... ' + format(tcpCWRFlag, '01b') + '... ....')
			if (extractedAttIndex == 9) or (extractedAttIndex == 0):
				self.unpackedInfo.append('ECE Flag: ' + '.... .' + format(tcpECEFlag, '01b') + '.. ....')
			if (extractedAttIndex == 10) or (extractedAttIndex == 0):
				self.unpackedInfo.append('URG Flag: ' + '.... ..' + format(tcpURGFlag, '01b') + '. ....')
			if (extractedAttIndex == 11) or (extractedAttIndex == 0):
				self.unpackedInfo.append('ACK Flag: ' + '.... ...' + format(tcpACKFlag, '01b') + ' ....')
			if (extractedAttIndex == 12) or (extractedAttIndex == 0):
				self.unpackedInfo.append('PSH Flag: ' + '.... .... ' + format(tcpPSHFlag, '01b') + '...')
			if (extractedAttIndex == 13) or (extractedAttIndex == 0):
				self.unpackedInfo.append('RST Flag: ' + '.... .... .' + format(tcpRSTFlag, '01b') + '..')
			if (extractedAttIndex == 14) or (extractedAttIndex == 0):
				self.unpackedInfo.append('SYN Flag: ' + '.... .... ..' + format(tcpSYNFlag, '01b') + '.')
			if (extractedAttIndex == 15) or (extractedAttIndex == 0):
				self.unpackedInfo.append('FIN Flag: ' + '.... .... ...' + format(tcpFINFlag, '01b'))
			if (extractedAttIndex == 16) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Window Size: ' + str(tcpWindowSize) + ' bytes')
			if (extractedAttIndex == 17) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Urgent Pointer: ' + str(tcpUrgentPointer))
			if (extractedAttIndex == 18) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Checksum: ' + format(tcpChecksum, '#04X'))
			if (extractedAttIndex == 19) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Options: ' + str(tcpoptions))		
			self.unpackedInfo.append('\n----------------------------------------')	
		else:
			if (extractedAttIndex == 1):
				return str(tcpSourcePort)
			if (extractedAttIndex == 2):
				return str(tcpDestPort)
			if (extractedAttIndex == 3):
				return str(tcpSeqNumber)
			if (extractedAttIndex == 4):
				return str(tcpAckNumber)
			if (extractedAttIndex == 5):
				return str(tcpDataOffset)
			if (extractedAttIndex == 6):
				return format(tcpReserved, '03b')
			if (extractedAttIndex == 7):
				return format(tcpNSFlag, '01b')
			if (extractedAttIndex == 8):
				return format(tcpCWRFlag, '01b')
			if (extractedAttIndex == 9):
				return format(tcpECEFlag, '01b')
			if (extractedAttIndex == 10):
				return format(tcpURGFlag, '01b')
			if (extractedAttIndex == 11):
				return format(tcpACKFlag, '01b')
			if (extractedAttIndex == 12):
				return format(tcpPSHFlag, '01b')
			if (extractedAttIndex == 13):
				return format(tcpRSTFlag, '01b')
			if (extractedAttIndex == 14):
				return format(tcpSYNFlag, '01b')
			if (extractedAttIndex == 15):
				return format(tcpFINFlag, '01b')
			if (extractedAttIndex == 16):
				return str(tcpWindowSize)
			if (extractedAttIndex == 17):
				return str(tcpUrgentPointer)
			if (extractedAttIndex == 18):
				return format(tcpChecksum, '#04X')
			if (extractedAttIndex == 19):
				return str(tcpoptions)			

	def udp(self, packet, extractedAttIndex, printKey):
		ethHeaderLength = 14
		ipHeaderLength = 20
		udpHeaderLength = 8
		begin = ethHeaderLength + ipHeaderLength
		end = begin + udpHeaderLength
		udpHeader = packet[begin:end]
		udpHeaderUnpacked = struct.unpack('!HHHH', udpHeader)
		udpSourcePort = udpHeaderUnpacked[0]
		udpDestPort = udpHeaderUnpacked[1]
		udpLength = udpHeaderUnpacked[2]
		udpChecksum = udpHeaderUnpacked[3]
		
		if printKey == 0:

			self.unpackedInfo.append('\n*******************\n******* UDP *******\n*******************')
			
			if (extractedAttIndex == 1) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Source Port: ' + str(udpSourcePort))
			if (extractedAttIndex == 2) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Destination Port: ' + str(udpDestPort))
			if (extractedAttIndex == 3) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Length: ' + str(udpLength) + ' bytes')
			if (extractedAttIndex == 4) or (extractedAttIndex == 0):
				self.unpackedInfo.append('Checksum: ' + format(udpChecksum, '#04X'))

				
			self.unpackedInfo.append('\n----------------------------------------')	
		else:
			if (extractedAttIndex == 1):
				return str(udpSourcePort)
			if (extractedAttIndex == 2):
				return str(udpDestPort)
			if (extractedAttIndex == 3):
				return str(udpLength)
			if (extractedAttIndex == 4):
				return format(udpChecksum, '#04X')
				
	def findProtocol(self, packet):

		packetProtocol = ''
		ethProtocol = self.eth(packet, 3, 1)
		ethProtocol = int(ethProtocol)

		if ethProtocol == 1544:
			packetProtocol = 1
		elif ethProtocol == 8:
			
			ipProtocol = self.ip(packet, 10, 1)
			ipProtocol = int(ipProtocol)
			if ipProtocol == 1:
				packetProtocol = 2
			elif ipProtocol == 6:
				packetProtocol = 3
			elif ipProtocol == 17:
				packetProtocol = 4
		return packetProtocol
		
	def extractAllAtt(self, packet):
		extractedAttIndex = 0
		printKey = 0
		self.eth(packet, extractedAttIndex, printKey)
		ethProtocol = self.eth(packet, 3, 1)
		ethProtocol = int(ethProtocol)
		if ethProtocol == 1544:
			self.arp(packet, extractedAttIndex, printKey)
		elif ethProtocol == 8:
			self.ip(packet, extractedAttIndex, printKey)
			ipProtocol = self.ip(packet, 10, 1)
			ipProtocol = int(ipProtocol)
			# If the protocol is 1, meaning ICMP
			# If the protocol is 6, meaning TCP
			# If the protocol is 17, meaning UDP
			if ipProtocol == 1:
				self.icmp(packet, extractedAttIndex, printKey)
			elif ipProtocol == 6:
				self.tcp(packet, extractedAttIndex, printKey)
			elif ipProtocol == 17:
				self.udp(packet, extractedAttIndex, printKey)

	def filterAndExtract(self, packet, filteredProtocolIndex, extractedAttIndex):

		protocolIndex = self.findProtocol(packet)
		if (filteredProtocolIndex == protocolIndex) or (filteredProtocolIndex == 0):
			printKey = 0
			if filteredProtocolIndex == 0:
				if extractedAttIndex >= 1:
					self.eth(packet, extractedAttIndex, printKey)
					unpackedInfo.append('\n----------------------------------------')
				elif extractedAttIndex == 0:
					self.extractAllAtt(packet)
			elif filteredProtocolIndex == 1:
				if extractedAttIndex >= 4:
					self.arp(packet, extractedAttIndex - 3, printKey)
				elif extractedAttIndex >= 1:
					self.eth(packet, extractedAttIndex, printKey)
					self.unpackedInfo.append('\n----------------------------------------')
				elif extractedAttIndex == 0:
					self.extractAllAtt(packet)
			elif filteredProtocolIndex == 2:
				if extractedAttIndex >= 17:
					self.icmp(packet, extractedAttIndex - 16, printKey)
				elif extractedAttIndex >= 4:
					self.ip(packet, extractedAttIndex - 3, printKey)
					self.unpackedInfo.append('\n----------------------------------------')	
				elif extractedAttIndex >= 1:	
					self.eth(packet, extractedAttIndex, printKey)
					self.unpackedInfo.append('\n----------------------------------------')
				elif extractedAttIndex == 0:
					self.extractAllAtt(packet)
			elif filteredProtocolIndex == 3:
				if extractedAttIndex >= 17:	
					self.tcp(packet, extractedAttIndex - 16, printKey)
				elif extractedAttIndex >= 4:
					self.ip(packet, extractedAttIndex - 3, printKey)
					self.unpackedInfo.append('\n----------------------------------------')	
				elif extractedAttIndex >= 1:	
					self.eth(packet, extractedAttIndex, printKey)
					self.unpackedInfo.append('\n----------------------------------------')	
				elif extractedAttIndex == 0:
					self.extractAllAtt(packet)
			elif filteredProtocolIndex == 4:
				if extractedAttIndex >= 17:	
					self.udp(packet, extractedAttIndex - 16, printKey)
				elif extractedAttIndex >= 4:
					self.ip(packet, extractedAttIndex - 3, printKey)
					self.unpackedInfo.append('\n----------------------------------------')	
				elif extractedAttIndex >= 1:	
					self.eth(packet, extractedAttIndex, printKey)
					self.unpackedInfo.append('\n----------------------------------------')	
				elif extractedAttIndex == 0:
					self.extractAllAtt(packet)
			return 0
		else:
			return 1
									
	def stop(self):
		self.sock.close()
		self.terminate()
		
	def close():
		try:
			print('Goodbye.')
			sys.exit()
		except KeyboardInterrupt:
			sys.exit()

	def sniff(self, filteredProtocolIndex, extractedAttIndex):
		while True:
			packet = self.sock.recvfrom(1234)
			packet = packet[0]				
			
			del self.unpackedInfo[:]
			
			
			filterAndExtract = self.filterAndExtract(packet, filteredProtocolIndex, extractedAttIndex)
			
			if filterAndExtract == 0:
				for i in range(len(self.unpackedInfo)):
					self.emit(QtCore.SIGNAL('updatePackets(QString)'), self.unpackedInfo[i])
						
	def __init__(self, filteredProtocolIndex, extractedAttIndex):
		QtCore.QThread.__init__(self)
		self.filteredProtocolIndex = filteredProtocolIndex
		self.extractedAttIndex = extractedAttIndex
		self.unpackedInfo = []
		def close():
			try:
				print('Goodbye.')
				sys.exit()
			except KeyboardInterrupt:
				sys.exit()
		try:
			#socket (raw) creation so that all packet types are accomodated
			self.sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
		except socket.error, msg:
			print('Socket could not be created. \nError code: ' + str(msg[0]) + '\nMessage: ' + msg[1])
			close()

	def __del__(self):
		self.wait()

	def run(self):
		self.sniff(self.filteredProtocolIndex, self.extractedAttIndex)

class Gui(QtGui.QWidget):	
	def startSniff(self):
		# Check to see if sniffing is 1, 0 if not sniffing --> bottom left info.
		if self.sniffKey == 1:
			self.sniffKey = 0
			self.sniffingLabel.setText('Sniffing...')
			
			filteredProtocolIndex = self.protocolComboBox.currentIndex()
			extractedAttIndex = self.attComboBox.currentIndex()
			
			self.sniffThread = SniffThread(filteredProtocolIndex, extractedAttIndex)
			self.connect(self.sniffThread, QtCore.SIGNAL('updatePackets(QString)'), self.updatePackets)
			
			self.sniffThread.start()
		
	def stopSniff(self):
		
		if self.sniffKey == 0:
			self.sniffKey = 1
			self.sniffingLabel.setText('Not sniffing.')
			self.sniffThread.stop()
		
	def updatePackets(self, unpackedInfo):
		self.packetEditText.append(unpackedInfo)
					
	def updateAtts(self, protocol):	
		allAttributes = ['All']
		ethAttributes = ['Destination Address', 'Source Address', 'EtherType']
		arpAttributes = ['Hardware Type', 'Protocol Type', 'Hardware Address Length', 'Protocol Address Length', 'Operation', 'Sender Hardware Address', 'Sender Protocol Address', 'Target Hardware Address', 'Target Protocol Address']
		ipAttributes = ['Version', 'Header Length', 'Differentiated Services Code Point', 'Explicit Congestion Notification', 'Total Length', 'Identification', 'Flags', 'Fragment Offset', 'Time to Live', 'Protocol', 'Header Checksum', 'Source Address', 'Destination Address','options']
		icmpAttributes = ['Type', 'Code', 'Checksum', 'Identifier (If available)', 'Sequence Number (If available)']
		tcpAttributes = ['Source Port', 'Destination Port', 'Sequence Number', 'Acknowledgment Number', 'Data Offset', 'Reserved', 'NS Flag', 'CWR Flag', 'ECE Flag', 'URG Flag', 'ACK Flag', 'PSH Flag', 'RST Flag', 'SYN Flag', 'FIN Flag', 'Window Size', 'Urgent Pointer', 'Checksum']
		udpAttributes = ['Source Port', 'Destination Port', 'Length', 'Checksum']
		
		self.attComboBox.clear()
		
		attributes = allAttributes + ethAttributes
		
		if protocol == 'ARP':
			attributes += arpAttributes
		elif protocol == 'ICMP':
			attributes += ipAttributes + icmpAttributes
		elif protocol == 'TCP':
			attributes += ipAttributes + tcpAttributes
		elif protocol == 'UDP':
			attributes += ipAttributes + udpAttributes
		self.attComboBox.insertItems(len(attributes), attributes)			
		
		if self.sniffKey == 0:
			self.stopSniff()

	def initGUI(self):
		
		protocols = ['All', 'ARP', 'ICMP', 'TCP', 'UDP']
		
		
		self.setWindowTitle('Packet Sniffer')
		self.resize(500, 425)

		
		grid = QtGui.QGridLayout()
		grid.setSpacing(10)

		
		startButton = QtGui.QPushButton('Start')
		stopButton = QtGui.QPushButton('Stop')
		
		
		protocolLabel = QtGui.QLabel('Protocols:')
		self.protocolComboBox = QtGui.QComboBox(self)
		self.protocolComboBox.insertItems(len(protocols), protocols)

		
		attLabel = QtGui.QLabel('Attributes:')
		self.attComboBox = QtGui.QComboBox(self)
		self.updateAtts('All')
		
		packetLabel = QtGui.QLabel('Packets:')
		self.packetEditText = QtGui.QTextEdit()
		self.packetEditText.setReadOnly(True)
		
		self.sniffingLabel = QtGui.QLabel('Not sniffing.')

		
		grid.addWidget(startButton, 1, 0, 1, 2)
		grid.addWidget(stopButton, 2, 0, 1, 2)

		grid.addWidget(protocolLabel, 3, 0, 1, 2)
		grid.addWidget(self.protocolComboBox, 4, 0, 1, 2)
		
		grid.addWidget(attLabel, 5, 0, 1, 2)
		grid.addWidget(self.attComboBox, 6, 0, 1, 2)

		grid.addWidget(packetLabel, 7, 0)
		grid.addWidget(self.packetEditText, 8, 0, 15, 1)

		grid.addWidget(self.sniffingLabel, 24, 0, 1, 2)
		
		
		startButton.clicked.connect(self.startSniff)
		stopButton.clicked.connect(self.stopSniff)
		self.connect(self.protocolComboBox, QtCore.SIGNAL('activated(QString)'), self.updateAtts)

		
		self.setLayout(grid) 
		self.show()

	def __init__(self):
		super(Gui, self).__init__()
		
		self.sniffKey = 1
		
		self.initGUI()

def main():
	
	app = QtGui.QApplication(sys.argv)
	gui = Gui()
	sys.exit(app.exec_())

if __name__ == '__main__':
    main()
