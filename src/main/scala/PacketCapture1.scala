/**
 * Created by root on 30/6/14.
 */
import java.util.Date
import java.lang.StringBuilder
import org.jnetpcap.Pcap
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.packet.PcapPacketHandler

object PacketCapture1 {
  def main(args: Array[String]){
    val snaplen = 64 * 1024 // Capture all packets, no trucation
    val flags = Pcap.MODE_PROMISCUOUS // capture all packets
    val timeout = 10 * 1000
    //val errbuf = new StringBuilder()

    val jsb = new java.lang.StringBuilder()
    val errbuf = new StringBuilder(jsb);
    val pcap = Pcap.openLive("eth0", snaplen, flags, timeout, errbuf)
    if (pcap == null) {
      println("Error : " + errbuf.toString())
    }
    println(pcap)
    val jpacketHandler = new PcapPacketHandler[String]() {

      def nextPacket(packet: PcapPacket, user: String) {
        println("Received packet at %s caplen=%4d len=%4d %s\n", new Date(packet.getCaptureHeader.timestampInMillis()),
          packet.getCaptureHeader.caplen(), packet.getCaptureHeader.wirelen(), user)
      }
    }
    pcap.loop(30, jpacketHandler, "jNetPcap works!")
    pcap.close()

  }
}
